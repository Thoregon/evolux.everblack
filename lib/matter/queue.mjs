/**
 * A queue is a secure store where the owner can communicate
 * with any user. Only this parties can read the entries
 *
 * Structure
 {
       t͛: {     // thoregon metadata
           owner: <owner_pubkey>,   // this is not a user public key, this key is unique and the keypair is available for the admin in its member entry
           salt: <salt>,
           members: {
               <user_pubkey_hash>: { nickname: '', icon: '', sharedkey: ''}, // the content is encrypted, can be decrypted with the owner pub key and the users priv key
           }
       }
       queue: [   // the content is encrypted with another shared secret key between user and owner; available for all users
           ...<content>>
       ]
  }
 *
 * @author: Bernhard Lukassen
 */

import PublicStore from "./publicstore.mjs";

export default class Queue extends PublicStore {


    send(message) {

    }

    onMessage(fn) {

    }

}
