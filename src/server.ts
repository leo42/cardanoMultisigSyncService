const express = require('express');
const fs = require('fs');
import * as crypto from 'crypto';
const app = express();
const http = require('http');
const { Server } = require("socket.io");
const axios = require('axios');
const { MongoClient } = require("mongodb");
import * as CardanoWasm from "@dcspark/cardano-multiplatform-lib-nodejs";
const MS = require('@emurgo/cardano-message-signing-nodejs');
const cors = require('cors');
//const uri =  process.env.MONGO_CONNECTION_STRING ||  "mongodb://localhost:27017/";


const uri =  process.env.MONGO_CONNECTION_STRING ||  "mongodb+srv://cluster0.9drtorw.mongodb.net/test?authMechanism=MONGODB-X509&authSource=%24external&tls=true&tlsCertificateKeyFile=secrets/mongo.pem"
const client = new MongoClient(uri,{
  retryWrites: true
});

console.log("uri", uri);
const connection = client.connect();
const LEYWAY = 1000 * 10; // 10 seconds
var transactions ;
var wallets ;
var users;



app.use(express.json());

app.use(cors());

app.post('/api/wallet', function(req, res) {
  console.log(req.body)
  const hash = walletHash(req.body)
  wallets.updateOne( {hash: hash}, {  $setOnInsert : { hash: hash , json: req.body , members: getMemebers(req.body), membersToUpdate: getMemebers(req.body), creationTime : Date.now() }}, {upsert: true})
  res.sendStatus(200);
});



app.post('/api/transaction', function(req, res) {
  try {
    const data = req.body;
    const tx = CardanoWasm.Transaction.from_cbor_hex(data.tx);
    const txBody = tx.body();

    // Calculate the hash of the transaction body
    const txBodyHash = CardanoWasm.hash_transaction(txBody);

    const signerAddedwitness = CardanoWasm.TransactionWitnessSet.from_cbor_hex(data.sigAdded);
    const vkeyWitness = signerAddedwitness.vkeywitnesses()?.get(0);

    if (!vkeyWitness) {
      console.log('No vkey witness found');
      return res.status(400).send('Invalid witness data');
    }

    const publicKey = vkeyWitness.vkey();
    const signature = vkeyWitness.ed25519_signature();

    // Verify the signature against the transaction body hash
    if (!publicKey.verify(txBodyHash.to_raw_bytes(), signature)) {
      console.log('Invalid signature');
      return
    }






  
    
      if(getMemebers(data.wallet).filter((member) => publicKey.hash().to_hex() === member).length === 0){
        console.log('Signer not member of wallet');
        return
      }

    const required_signers = tx.body().to_js_value().required_signers
    transactions.findOne({ hash: CardanoWasm.hash_transaction(tx.body()).to_hex() }).then((existingTx) => {
      const existingMembersToUpdate = existingTx ? existingTx.membersToUpdate || [] : [];
      const existingSignatures = existingTx ? existingTx.signatures || {} : {};
      const membersToUpdate = required_signers.filter((member) => member !== publicKey.hash().to_hex()).concat(existingMembersToUpdate);
      const signatures = existingSignatures.hasOwnProperty(publicKey.hash().to_hex()) ? existingSignatures : {...existingSignatures, [publicKey.hash().to_hex()]: data.sigAdded};
      // if the transaction exist update the signatures and add to the membersToUpdate list

      transactions.updateOne( {hash: CardanoWasm.hash_transaction(tx.body()).to_hex()}, { $set : { hash:  CardanoWasm.hash_transaction(tx.body()).to_hex() , transaction :  tx.to_canonical_cbor_hex() , signatures: signatures ,  requiredSigners : tx.body().to_js_value().required_signers , membersToUpdate:membersToUpdate  , lastUpdate : Date.now(), wallet: walletHash(data.wallet) }}, {upsert: true})
    })

    }catch(e){
        console.log(e)
      }


   
  res.sendStatus(200);
});



const server = http.createServer(app);
const io = new Server(server, {cors: {origin: "*"}});


connection.then(async () => {
  console.log("Connected correctly to server");

  const db = client.db('MWallet');
  if (!db) {
    await client.db('MWallet').createCollection("transactions");
  
  }
  


  // Check and initialize collections if they do not exist
  const collections = await db.listCollections().toArray();
  const collectionNames = collections.map(col => col.name);

  if (!collectionNames.includes("transactions")) {
    await db.createCollection("transactions");
  }
  transactions = db.collection("transactions");

  if (!collectionNames.includes("Users")) {
    await db.createCollection("Users");
  }
  users = db.collection("Users");

  if (!collectionNames.includes("wallets")) {
    await db.createCollection("wallets");
  }
  wallets = db.collection("wallets");
  console.log("Collections initialized", users, transactions, wallets);
  watchWallets().catch(console.error);
}).catch(err => {
  console.log(err.stack);
  process.exit(1);
});

client.on("close", () => {
  console.error("Lost MongoDB connection");
  process.exit(1);
});

client.on("error", (err) => {
  console.error("MongoDB error:", err);
});

process.on("SIGINT", () => {
  console.log("Closing MongoDB connection");
  client.close().then(() => {
    console.log("MongoDB connection closed");
    process.exit(0);
  });
});




let verification = new Map();
let subscriptions = new Map();
//console.log(config.Ed25519KeyHash)

main()
  
  async function main() {


io.on('connection', (socket ) => {
  console.info(`Client connected [id=${socket.id}]`);
  
  socket.on('disconnect', () => {
    if (verification[socket.id] && verification[socket.id].state === "Authenticated"){
      users.findOneAndUpdate({PubkeyHash: verification[socket.id].user}, { $set : { lastLogin: Date.now()}})
    }
    verification.delete(socket.id);
    subscriptions.delete(socket.id);
    console.info(`Client gone [id=${socket.id}]`); 
  });
  
 
  socket.on('authentication_start', (data) => {
    
     users.findOne({authenticationToken: data.token} ).then((user) => {
          if (user){
            users.findOneAndUpdate({authenticationToken: data.token}, { $set : { lastLogin: Date.now()}})
            verification[socket.id] = { state: "Authenticated" , user: user.PubkeyHash}
            subscribeToWallets( socket,  data.wallets )            
            findNewWallets(user.PubkeyHash, socket )
          }else{
            verification[socket.id] = { state: "Challenge" , challenge_string: stringToHex("challenge_" + (crypto.randomBytes(36).toString('hex')))}
            socket.emit('authentication_challenge', {challenge: verification[socket.id].challenge_string})
          }
    }).catch((err) => {
      console.log(err)
      socket.emit('error', {error: "Authentication token not found"})
      socket.disconnect() 
    })
  })



  socket.on('authentication_response', (data) => {
    const { address, signature } = data;
    const { challenge_string } = verification[socket.id];
    try{
      const PubkeyHash =  verify( address, challenge_string, signature)
      const authenticationToken = crypto.randomBytes(36).toString('hex')


      users.findOneAndUpdate( {PubkeyHash: PubkeyHash}, { $set : { PubkeyHash: PubkeyHash , authenticationToken: authenticationToken , issueTime : Date.now(), lastLogin: Date.now() }}, {upsert: true}).then((user) => {
        if (user){
            findNewWallets(PubkeyHash, socket)
            subscribeToWallets( socket,  data.wallets ) 
        }else{
            findNewWallets(PubkeyHash,  socket)
            subscribeToWallets( socket,  data.wallets ) 
        }
      })
      socket.emit('authentication_success', {authenticationToken: authenticationToken})
      socket.verification= { state: "Authenticated" , user: PubkeyHash}
      verification[socket.id] = { state: "Authenticated" , user: PubkeyHash}

    }catch(err){
      console.log(err)
      socket.emit('error', {error: "Signature verification failed"})
      socket.disconnect()
    } 
 })

 socket.on("subscribe", (data) => {
  if(verification[socket.id] && verification[socket.id].state === "Authenticated"){
    //Date.now() minus 4 hours to get all transactions since last login
    
    subscribeToWallets( socket,  [data] )  
  }else {
    socket.emit('error', { error: "Not authenticated" })
    socket.disconnect()
  }
 })

 socket.on('loadWallets', (data) => {
  if(verification[socket.id] && verification[socket.id].state === "Authenticated"){
    let walletsFound = wallets.find({members: verification[socket.id].user})
    walletsFound.toArray().then((walletsFound) => {
    if (walletsFound.length > 0) {
      socket.emit('wallets_found', { wallets: walletsFound })
    } else {
      socket.emit('wallets_found', { wallets: [] })
    }
  }).catch((err) => {
    console.log(err)
    socket.emit('error', {error: "Wallets not found"})
    socket.disconnect() 
  })

}else {
    socket.emit('error', { error: "Not authenticated" })
  }
})

  
});

};

function subscribeToWallets(socket, wallets ){
  
   wallets.map((wallet) => {

    if (getMemebers(wallet).includes(verification[socket.id].user)){  
      watchTransactions( socket,walletHash(wallet) ).catch(console.error);
      findNewTransactions(walletHash(wallet),  socket)
  }
  })
}


app.get('/api', function(req, res) {
  res.sendfile('public/index.html');
});

//use express to submit a new wallet into the database 


let getMemebers = function (json : any){
  let members: string[] = [];
  if(json.type == "sig"){
    return [json.keyHash]
  }else if(json.type === "any" || json.type === "all" || json.type === "at_least"){
    for(let i = 0; i < json.scripts.length; i++){
      //how do I fix this error? 

      members = members.concat( getMemebers(json.scripts[i]))
    }
  }else if(json.type === "after" || json.type === "before"){
    return []
  }
  return members
}

const verify = (address, payload, walletSig) => {
  const coseSign1 = MS.COSESign1.from_bytes(Buffer.from(walletSig.signature, 'hex'));
  const coseKey = MS.COSEKey.from_bytes(Buffer.from(walletSig.key, 'hex'));
  const payloadCose = coseSign1.payload();
  if (verifyPayload(payload, payloadCose))
    throw new Error('Payload does not match');
  const keyHeaders = coseKey.header(MS.Label.new_int( MS.Int.new_i32(-2))).as_bytes()
  const protectedHeaders = coseSign1
    .headers()
    .protected()
    .deserialized_headers();
  const addressCose =CardanoWasm.Address.from_raw_bytes(
    protectedHeaders.header(MS.Label.new_text('address')).as_bytes()
  );
  const publicKeyCose = CardanoWasm.PublicKey.from_bytes( keyHeaders );

  if (!verifyAddress(address, addressCose, publicKeyCose))
   throw new Error('Could not verify because of address mismatch');

  const signature =CardanoWasm.Ed25519Signature.from_raw_bytes(coseSign1.signature());
  const data = coseSign1.signed_data().to_bytes();
  if ( publicKeyCose.verify(data, signature))
      return  publicKeyCose.hash().to_hex()
};

const verifyPayload = (payload, payloadCose) => {
  return Buffer.from(payloadCose, 'hex').compare(Buffer.from(payload, 'hex'));
};

function stringToHex(str) {
  var hex = '';
  for (var i = 0; i < str.length; i++) {
    hex += '' + str.charCodeAt(i).toString(16);
  }
  return hex;
};

const verifyAddress = (address: string, addressCose: CardanoWasm.Address, publicKeyCose: CardanoWasm.PublicKey) => {
  console.log("Verifying address", address, addressCose.to_bech32(), publicKeyCose.hash().to_hex())

  const checkAddress = CardanoWasm.Address.from_bech32(address);
  if (addressCose.to_bech32() !== checkAddress.to_bech32()) 
    {
      console.log("Address bench32 mismatch")
      return false;
    }
  // check if BaseAddress
  try {
    const baseAddress = CardanoWasm.BaseAddress.from_address(addressCose);

    //reconstruct address
    const paymentKeyHash = publicKeyCose.hash();

    if (checkAddress.payment_cred()?.to_canonical_cbor_hex()  !== CardanoWasm.Credential.new_pub_key(paymentKeyHash).to_canonical_cbor_hex()
      || checkAddress.staking_cred()?.to_canonical_cbor_hex() !== baseAddress!.stake().to_canonical_cbor_hex()
    )


    {
      console.log("Address reconstructed mismatch")
      return false;
    }


    return true;
  } catch (e) {
    console.log("Address mismatch catch 1", e.message)
  }
  // check if RewardAddress
  try {
    //reconstruct address
    const stakeKeyHash = publicKeyCose.hash().to_hex();
    const reconstructedAddress = CardanoWasm.RewardAddress.new(
      checkAddress.network_id(),
      CardanoWasm.Credential.from_cbor_hex(stakeKeyHash)
    );
    if (
      checkAddress.to_bech32() !== reconstructedAddress.to_address().to_bech32()
    )
    {
      console.log("Address reconstructed mismatch 2")
      return false;
    }


    return true;
  } catch (e) {
    console.log("Address mismatch", e.message)
  }
  console.log("Address mismatch expired")
  return false;
};


function findNewWallets(PubKeyHash, socket){
  
  let walletsFound = wallets.find({members: PubKeyHash,  membersToUpdate: PubKeyHash  })
  walletsFound.toArray().then((walletsFound) => {
  if (walletsFound.length > 0) {
    socket.emit('wallets_found', { wallets: walletsFound })
  }
  walletsFound.forEach((wallet) => {
    wallets.updateOne({ _id: wallet._id }, { $pull: { membersToUpdate: PubKeyHash } })
  })

}).catch((err) => {
  console.log(err)
  socket.emit('error', {error: "Wallets not found"})
  socket.disconnect() 
})
}

function findNewTransactions(wallet, socket, ){
  // membersToUpdate is a list of members that need to be updated with the new transaction
  const PubKeyHash = verification[socket.id].user

  let TransactionsFound = transactions.find({wallet: wallet, membersToUpdate: PubKeyHash })
  
  TransactionsFound.toArray().then((TransactionsFound) => {
  if (TransactionsFound.length > 0) {
    socket.emit('transaction', { transactions: TransactionsFound })
  } 
  TransactionsFound.forEach((transaction) => {
    transactions.updateOne({ _id: transaction._id }, { $pull: { membersToUpdate: PubKeyHash } })
  })

}).catch((err) => {
  console.log(err)
  socket.emit('error', {error: "Transactions not found"})
  socket.disconnect()
})


}

async function watchWallets()  {
  const changeStream = wallets.watch();
  changeStream.on('change', async (change) => {
    if (change.operationType === 'update' || change.operationType ===  'insert') {
      
      
      const wallet = await wallets.findOne({ _id: change.documentKey._id });
      const signers = wallet.members;
      const RelevantSockets : String[] = []
      Object.keys(verification).map( (key) => {
        if( wallet.membersToUpdate.includes(verification[key].user) ){RelevantSockets.push(key)}}
      )
      if (RelevantSockets.length > 0) {
        RelevantSockets.forEach((socket) => {
          const sock = io.sockets.sockets.get(socket)
          if (sock && sock.connected) {
            sock.emit('wallets_found', { wallets: [wallet] });
            wallets.updateOne({ _id: wallet._id }, { $pull: { membersToUpdate: verification[sock.id].user } })
          }
        });
      }
    }
  });
}


async function watchTransactions( socket , wallet ) {
  // membersToUpdate is a list of members that need to be updated with the new transaction
  const PubKeyHash = verification[socket.id].user

  const pipeline = [
    {
      $match: {
        operationType: { $in: ["update", "insert"] },
        "fullDocument.membersToUpdate": PubKeyHash,
        "fullDocument.wallet": wallet
      
      }
    }
  ];
  
  const options = { fullDocument: "updateLookup" };
  const changeStream = transactions.watch( pipeline , options );

  changeStream.on('change', async (change) => {
    const transaction = await transactions.findOne({ _id: change.documentKey._id });
    socket.emit('transaction', { transactions: [ transaction] });
    transactions.updateOne({ _id: transaction._id }, { $pull: { membersToUpdate: PubKeyHash } })
  });

  socket.on('disconnect', () => {
    changeStream.close();
  });
}




function walletHash(wallet) {
  //remove the name field from the wallet object recursively
  function removeName(obj) {
    if (typeof obj === 'object') {
      if (Array.isArray(obj)) {
        obj.forEach((item) => {
          removeName(item);
        });
      } else {
        delete obj.name;
        Object.keys(obj).forEach((key) => {
          removeName(obj[key]);
        });
      }
    }
  }
  ;
  // create a deep copy of the wallet object

  const cleanWallet = JSON.parse(JSON.stringify(wallet));
  removeName(cleanWallet)
 return crypto.createHash('sha256').update(JSON.stringify(cleanWallet)).digest('hex');

}


server.listen(3001, () => {
  console.log('listening on *:3001');
});
