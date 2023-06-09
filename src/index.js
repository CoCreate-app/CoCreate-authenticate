const jwt = require('jsonwebtoken');

// Configuration
const tokenExpiration = 60; // Token expiration in minutes

// Array to store key pairs
const keyPairs = new Map();

// Map to store authenticated user
const users = new Map();

// TODO: user can have multiple sessions
const activeSessions = new Map();

// crud.listen('createDocument', function (data) {
//     if (data.document && data.document[0] && data.document[0].type === 'keyPair')
//         keyPairs.set(data.document[0]._id, data.document[0]);
// });

// crud.listen('deleteDocument', function (data) {
//     if (data.document && data.document[0] && data.document[0].type === 'keyPair')
//         keyPairs.delete(data.document[0]._id);
// });

// Create new RSA key pair
function createKeyPair() {
    const { privateKey, publicKey } = jwt.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    const keyPair = {
        _id: crud.ObjectId(),
        privateKey,
        publicKey,
        created: new Date().getTime(), // Store as timestamp
        expires: new Date().getTime() + tokenExpiration * 60 * 1000 * 2, // Convert minutes to milliseconds
    };

    keyPairs.set(keyPair._id, keyPair);

    // crud.createDocument({
    //     collection: 'keys',
    //     document: {
    //         ...keyPair,
    //     },
    //     organization_id: process.env.organization_id,
    // });

    return keyPair;
}

// Function to retrieve keys from the database (example using CRUD operations)
function readKeyPairs() {
    const keys = crud.readDocument({
        collection: 'keys',
        filter: {
            query: [
                { name: 'type', value: 'keyPair' },
            ],
        },
        organization_id: process.env.organization_id,
    });

    // Add retrieved key pairs to the keyPairs array
    if (keys.document && keys.document.length) {
        keys.document.forEach((keyPair) => {
            keyPairs.set(keyPair._id, keyPair);
        });
    }
}

// Delete new RSA key pair
function deleteKeyPair(keyPair) {
    keyPairs.delete(keyPair._id)
    // crud.deleteDocument({
    //     collection: 'keys',
    //     document: {
    //         _id: keyPair._id,
    //         type: 'keyPair'
    //     },
    //     organization_id: process.env.organization_id,
    // });
}

// Function to sign a new token using the newest keyPair
function encodeToken(payload) {
    let keyPair = null
    const currentTime = new Date().getTime();
    for (let [key, value] of keyPairs) {
        if (currentTime > value.expires) {
            deleteKeyPair(value);
        } else {
            keyPair = value
        }
    }

    if (!keyPair) {
        keyPair = createKeyPair();
    }

    // TODO: payload could have previous user ip and device information which we could use to comapre to current ip and device information 

    const token = jwt.sign(payload, keyPair.privateKey, { expiresIn: tokenExpiration * 60 });
    users.set(token, { _id: payload.user._id, expires: new Date().getTime() + tokenExpiration * 60 * 1000 })
    return token;
}

// Verify and decode a token using the available keys
function decodeToken(req) {
    const headers = req.headers;
    const token = headers['sec-websocket-protocol'];
    const currentTime = new Date().getTime();

    let user = users.get(token)
    if (user && currentTime < user.expires)
        return user._id;

    users.delete(token)
    return null

}

// readKeyPairs();

module.exports = { encodeToken, decodeToken };
