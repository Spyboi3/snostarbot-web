require('dotenv').config();
const express=require('express');
const cors=require('cors');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');
const path=require('path');
const crypto=require('crypto');

const app=express();
const PORT=process.env.PORT||3001;
const JWT_SECRET=process.env.JWT_SECRET||'snostarbot_jwt_secret_change_me';
const db=new Database(path.join(__dirname,'snostarbot_web.db'));

// Init DB
db.exec(`
  CREATE TABLE IF NOT EXISTS web_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    telegram_id INTEGER UNIQUE,
    telegram_username TEXT,
    plan TEXT DEFAULT 'free',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS web_wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    label TEXT,
    address TEXT,
    encrypted_key TEXT,
    wallet_index INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS web_mints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    contract TEXT,
    status TEXT,
    tx_hash TEXT,
    chain TEXT,
    price TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(cors({origin:'*'}));
app.use(express.json());
app.use(express.static('public'));

// Encrypt/decrypt
const ENC_KEY=process.env.WALLET_ENCRYPTION_KEY||'snostarbot_default_key';
const KEY=crypto.scryptSync(ENC_KEY,'snostarbot_salt',32);

function encrypt(text){
  const iv=crypto.randomBytes(16);
  const cipher=crypto.createCipheriv('aes-256-gcm',KEY,iv);
  const enc=Buffer.concat([cipher.update(text,'utf8'),cipher.final()]);
  const tag=cipher.getAuthTag();
  return iv.toString('hex')+':'+tag.toString('hex')+':'+enc.toString('hex');
}

function decrypt(enc){
  if(!enc)return null;
  if(enc.startsWith('0x'))return enc;
  try{
    const[ivH,tagH,dataH]=enc.split(':');
    const iv=Buffer.from(ivH,'hex');
    const tag=Buffer.from(tagH,'hex');
    const data=Buffer.from(dataH,'hex');
    const d=crypto.createDecipheriv('aes-256-gcm',KEY,iv);
    d.setAuthTag(tag);
    return d.update(data,'','utf8')+d.final('utf8');
  }catch(e){return enc;}
}

// Auth middleware
function auth(req,res,next){
  const token=req.headers.authorization?.replace('Bearer ','');
  if(!token)return res.status(401).json({error:'Unauthorized'});
  try{
    req.user=jwt.verify(token,JWT_SECRET);
    next();
  }catch(e){res.status(401).json({error:'Invalid token'});}
}

// ROUTES

// Register with email
app.post('/api/auth/register',async(req,res)=>{
  const{email,password}=req.body;
  if(!email||!password)return res.status(400).json({error:'Email and password required'});
  if(password.length<8)return res.status(400).json({error:'Password must be at least 8 characters'});
  try{
    const hash=await bcrypt.hash(password,12);
    const user=db.prepare('INSERT INTO web_users (email,password) VALUES (?,?)').run(email.toLowerCase(),hash);
    const token=jwt.sign({id:user.lastInsertRowid,email},JWT_SECRET,{expiresIn:'30d'});
    res.json({token,user:{id:user.lastInsertRowid,email,plan:'free'}});
  }catch(e){
    if(e.message.includes('UNIQUE'))return res.status(400).json({error:'Email already registered'});
    res.status(500).json({error:e.message});
  }
});

// Login with email
app.post('/api/auth/login',async(req,res)=>{
  const{email,password}=req.body;
  const user=db.prepare('SELECT * FROM web_users WHERE email=?').get(email?.toLowerCase());
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
  let user=db.prepare('SELECT * FROM web_users WHERE telegram_id=?').get(telegram_id);
  if(!user){
    const result=db.prepare('INSERT INTO web_users (telegram_id,telegram_username) VALUES (?,?)').run(telegram_id,telegram_username||'');
    user={id:result.lastInsertRowid,telegram_id,telegram_username,plan:'free'};
  }
  const token=jwt.sign({id:user.id,telegram_id},JWT_SECRET,{expiresIn:'30d'});
  res.json({token,user:{id:user.id,plan:user.plan,telegram_username:user.telegram_username||telegram_username}});
});

// Get current user
app.get('/api/me',auth,(req,res)=>{
  const user=db.prepare('SELECT id,email,telegram_username,plan,created_at FROM web_users WHERE id=?').get(req.user.id);
  if(!user)return res.status(404).json({error:'User not found'});
  res.json(user);
});

// Get wallets
app.get('/api/wallets',auth,(req,res)=>{
  const wallets=db.prepare('SELECT id,label,address,wallet_index,created_at FROM web_wallets WHERE user_id=? ORDER BY wallet_index').all(req.user.id);
  res.json(wallets);
});

// Add wallet
app.post('/api/wallets',auth,(req,res)=>{
  const{label,privateKey,address}=req.body;
  if(!privateKey||!address)return res.status(400).json({error:'Private key and address required'});
  const count=db.prepare('SELECT COUNT(*) as c FROM web_wallets WHERE user_id=?').get(req.user.id);
  const encKey=encrypt(privateKey);
  const idx=(count.c||0)+1;
  const result=db.prepare('INSERT INTO web_wallets (user_id,label,address,encrypted_key,wallet_index) VALUES (?,?,?,?,?)').run(req.user.id,label||'Wallet '+idx,address,encKey,idx);
  res.json({id:result.lastInsertRowid,label:label||'Wallet '+idx,address,wallet_index:idx});
});

// Delete wallet
app.delete('/api/wallets/:id',auth,(req,res)=>{
  db.prepare('DELETE FROM web_wallets WHERE id=? AND user_id=?').run(req.params.id,req.user.id);
  res.json({success:true});
});

// Get mint history
app.get('/api/mints',auth,(req,res)=>{
  const mints=db.prepare('SELECT * FROM web_mints WHERE user_id=? ORDER BY created_at DESC LIMIT 50').all(req.user.id);
  res.json(mints);
});

// Detect contract info
app.post('/api/detect',auth,async(req,res)=>{
  const{contract,chain}=req.body;
  if(!contract)return res.status(400).json({error:'Contract address required'});
  try{
    const{ethers}=require('ethers');
    const rpcs={ethereum:process.env.RPC_URL||'https://eth.llamarpc.com',base:process.env.BASE_RPC_URL||'https://mainnet.base.org',abstract:process.env.ABSTRACT_RPC_URL||'https://api.mainnet.abs.xyz'};
    const rpc=rpcs[chain||'ethereum'];
    const provider=new ethers.JsonRpcProvider(rpc);
    // Try SeaDrop
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
    // Get supply
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

app.listen(PORT,()=>console.log('SnostarBot API running on port '+PORT));

// Serve index.html for all non-API routes
const fs=require('fs');
app.get('*',(req,res)=>{
  if(req.path.startsWith('/api'))return res.status(404).json({error:'Not found'});
  const file=path.join(__dirname,'public',req.path==='/'?'index.html':req.path);
  if(fs.existsSync(file))return res.sendFile(file);
  res.sendFile(path.join(__dirname,'public','index.html'));
});
