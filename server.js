require('dotenv').config();
const express=require('express');
const cors=require('cors');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcryptjs');
const crypto=require('crypto');
const path=require('path');
const fs=require('fs');

const app=express();
const PORT=process.env.PORT||3001;
const JWT_SECRET=process.env.JWT_SECRET||'snostarbot_jwt_secret';

// Simple JSON DB
const DB_FILE=path.join(__dirname,'db.json');
function readDB(){
  if(!fs.existsSync(DB_FILE))return{users:[],wallets:[],mints:[]};
  try{return JSON.parse(fs.readFileSync(DB_FILE,'utf8'));}catch(e){return{users:[],wallets:[],mints:[]};}
}
function writeDB(data){fs.writeFileSync(DB_FILE,JSON.stringify(data,null,2));}
function nextId(arr){return arr.length?Math.max(...arr.map(x=>x.id||0))+1:1;}

app.use(cors({origin:'*'}));
app.use(express.json());
app.use(express.static('public'));

// Encryption
const ENC_KEY=process.env.WALLET_ENCRYPTION_KEY||'snostarbot_default_key';
const KEY=crypto.scryptSync(ENC_KEY,'snostarbot_salt',32);
function encrypt(text){
  const iv=crypto.randomBytes(16);
  const cipher=crypto.createCipheriv('aes-256-gcm',KEY,iv);
  const enc=Buffer.concat([cipher.update(text,'utf8'),cipher.final()]);
  const tag=cipher.getAuthTag();
  return iv.toString('hex')+':'+tag.toString('hex')+':'+enc.toString('hex');
}

// Auth middleware
function auth(req,res,next){
  const token=req.headers.authorization?.replace('Bearer ','');
  if(!token)return res.status(401).json({error:'Unauthorized'});
  try{req.user=jwt.verify(token,JWT_SECRET);next();}
  catch(e){res.status(401).json({error:'Invalid token'});}
}

// Register
app.post('/api/auth/register',async(req,res)=>{
  const{email,password}=req.body;
  if(!email||!password)return res.status(400).json({error:'Email and password required'});
  if(password.length<8)return res.status(400).json({error:'Password must be at least 8 characters'});
  const db=readDB();
  if(db.users.find(u=>u.email===email.toLowerCase()))return res.status(400).json({error:'Email already registered'});
  const hash=await bcrypt.hash(password,12);
  const user={id:nextId(db.users),email:email.toLowerCase(),password:hash,plan:'free',created_at:new Date().toISOString()};
  db.users.push(user);
  writeDB(db);
  const token=jwt.sign({id:user.id,email:user.email},JWT_SECRET,{expiresIn:'30d'});
  res.json({token,user:{id:user.id,email:user.email,plan:'free'}});
});

// Login
app.post('/api/auth/login',async(req,res)=>{
  const{email,password}=req.body;
  const db=readDB();
  const user=db.users.find(u=>u.email===email?.toLowerCase());
  if(!user||!user.password)return res.status(401).json({error:'Invalid email or password'});
  const match=await bcrypt.compare(password,user.password);
  if(!match)return res.status(401).json({error:'Invalid email or password'});
  const token=jwt.sign({id:user.id,email:user.email},JWT_SECRET,{expiresIn:'30d'});
  res.json({token,user:{id:user.id,email:user.email,plan:user.plan,telegram_username:user.telegram_username}});
});

// Telegram login
app.post('/api/auth/telegram',async(req,res)=>{
  const{telegram_id,telegram_username}=req.body;
  if(!telegram_id)return res.status(400).json({error:'Telegram ID required'});
  const db=readDB();
  let user=db.users.find(u=>u.telegram_id===telegram_id);
  if(!user){
    user={id:nextId(db.users),telegram_id,telegram_username,plan:'free',created_at:new Date().toISOString()};
    db.users.push(user);
    writeDB(db);
  }
  const token=jwt.sign({id:user.id,telegram_id},JWT_SECRET,{expiresIn:'30d'});
  res.json({token,user:{id:user.id,plan:user.plan,telegram_username:user.telegram_username||telegram_username}});
});

// Me
app.get('/api/me',auth,(req,res)=>{
  const db=readDB();
  const user=db.users.find(u=>u.id===req.user.id);
  if(!user)return res.status(404).json({error:'User not found'});
  res.json({id:user.id,email:user.email,telegram_username:user.telegram_username,plan:user.plan,created_at:user.created_at});
});

// Wallets
app.get('/api/wallets',auth,(req,res)=>{
  const db=readDB();
  const wallets=db.wallets.filter(w=>w.user_id===req.user.id).map(w=>({id:w.id,label:w.label,address:w.address,wallet_index:w.wallet_index,created_at:w.created_at}));
  res.json(wallets);
});

app.post('/api/wallets',auth,(req,res)=>{
  const{label,privateKey,address}=req.body;
  if(!privateKey||!address)return res.status(400).json({error:'Private key and address required'});
  const db=readDB();
  const userWallets=db.wallets.filter(w=>w.user_id===req.user.id);
  const encKey=encrypt(privateKey);
  const wallet={id:nextId(db.wallets),user_id:req.user.id,label:label||'Wallet '+(userWallets.length+1),address,encrypted_key:encKey,wallet_index:userWallets.length+1,created_at:new Date().toISOString()};
  db.wallets.push(wallet);
  writeDB(db);
  res.json({id:wallet.id,label:wallet.label,address:wallet.address,wallet_index:wallet.wallet_index});
});

app.delete('/api/wallets/:id',auth,(req,res)=>{
  const db=readDB();
  db.wallets=db.wallets.filter(w=>!(w.id===parseInt(req.params.id)&&w.user_id===req.user.id));
  writeDB(db);
  res.json({success:true});
});

// Mints
app.get('/api/mints',auth,(req,res)=>{
  const db=readDB();
  const mints=db.mints.filter(m=>m.user_id===req.user.id).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).slice(0,50);
  res.json(mints);
});

// Detect contract
app.post('/api/detect',auth,async(req,res)=>{
  const{contract,chain}=req.body;
  if(!contract)return res.status(400).json({error:'Contract address required'});
  try{
    const{ethers}=require('ethers');
    const rpcs={ethereum:process.env.RPC_URL||'https://eth.llamarpc.com',base:process.env.BASE_RPC_URL||'https://mainnet.base.org',abstract:process.env.ABSTRACT_RPC_URL||'https://api.mainnet.abs.xyz'};
    const rpc=rpcs[chain||'ethereum'];
    const provider=new ethers.JsonRpcProvider(rpc);
    const SEADROP='0x00005ea00ac477b1030ce78506496e8c2de24bf5';
    const abi=['function getPublicDrop(address) view returns (tuple(uint80 mintPrice,uint48 startTime,uint48 endTime,uint16 maxTotalMintableByWallet,uint16 feeBps,bool restrictFeeRecipients))'];
    let mintPrice='0';let maxPerWallet=1;let startTime=null;let endTime=null;let isLive=false;
    try{
      const seadrop=new ethers.Contract(SEADROP,abi,provider);
      const drop=await seadrop.getPublicDrop(contract);
      if(drop){
        mintPrice=ethers.formatEther(drop.mintPrice);
        maxPerWallet=parseInt(drop.maxTotalMintableByWallet.toString());
        startTime=new Date(Number(drop.startTime)*1000).toISOString();
        endTime=new Date(Number(drop.endTime)*1000).toISOString();
        const now=Date.now();
        isLive=now>=Number(drop.startTime)*1000&&now<=Number(drop.endTime)*1000;
      }
    }catch(e){}
    let totalSupply=0;let maxSupply=0;
    try{
      const c=new ethers.Contract(contract,['function totalSupply() view returns (uint256)','function maxSupply() view returns (uint256)'],provider);
      const[ts,ms]=await Promise.all([c.totalSupply().catch(()=>0n),c.maxSupply().catch(()=>0n)]);
      totalSupply=parseInt(ts.toString());
      maxSupply=parseInt(ms.toString());
    }catch(e){}
    res.json({contract,chain:chain||'ethereum',mintPrice,maxPerWallet,startTime,endTime,isLive,totalSupply,maxSupply,remaining:maxSupply>0?maxSupply-totalSupply:null});
  }catch(e){res.status(500).json({error:e.message});}
});

// Serve frontend
app.get('*',(req,res)=>{
  if(req.path.startsWith('/api'))return res.status(404).json({error:'Not found'});
  const file=path.join(__dirname,'public',req.path==='/'?'index.html':req.path.slice(1));
  if(fs.existsSync(file))return res.sendFile(file);
  res.sendFile(path.join(__dirname,'public','index.html'));
});

app.listen(PORT,()=>console.log('SnostarBot API running on port '+PORT));
