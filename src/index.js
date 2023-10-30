const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('@cocreate/utils');

// Configuration
const tokenExpiration = 60; // Token expiration in minutes

// Array to store key pairs
const keyPairs = new Map();

// Map to store authenticated user
const users = new Map();

// TODO: user can have multiple sessions
const activeSessions = new Map();

// crud.listen('create.object', function (data) {
//     if (data.object && data.object[0] && data.object[0].type === 'keyPair')
//         keyPairs.set(data.object[0]._id, data.object[0]);
// });

// crud.listen('delete.object', function (data) {
//     if (data.object && data.object[0] && data.object[0].type === 'keyPair')
//         keyPairs.delete(data.object[0]._id);
// });

// Create new RSA key pair
function createKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    const keyPair = {
        _id: ObjectId().toString(),
        privateKey,
        publicKey,
        created: new Date().getTime(), // Store as timestamp
        expires: new Date().getTime() + tokenExpiration * 60 * 1000 * 2, // Convert minutes to milliseconds
    };

    keyPairs.set(keyPair._id, keyPair);

    // crud.send({
    //     method: 'object.create',
    //     array: 'keys',
    //     object: {
    //         ...keyPair,
    //     },
    //     organization_id: process.env.organization_id,
    // });

    return keyPair;
}

// Function to retrieve keys from the database (example using CRUD operations)
function readKeyPairs() {
    const keys = crud.send({
        method: 'object.read',
        array: 'keys',
        object: {
            $filter: {
                query: [
                    { key: 'type', value: 'keyPair' },
                ],
            }
        },
        organization_id: process.env.organization_id,
    });

    // Add retrieved key pairs to the keyPairs array
    if (keys.object && keys.object.length) {
        keys.object.forEach((keyPair) => {
            keyPairs.set(keyPair._id, keyPair);
        });
    }
}

// Delete new RSA key pair
function deleteKeyPair(keyPair) {
    keyPairs.delete(keyPair._id)
    // crud.send({
    //     method: 'object.delete',
    //     array: 'keys',
    //     object: {
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

    const token = jwt.sign(payload, keyPair.privateKey, { algorithm: 'RS256', expiresIn: tokenExpiration * 60 });
    users.set(token, { _id: payload.user_id, expires: new Date().getTime() + tokenExpiration * 60 * 1000 })
    return token;
}

// Verify and decode a token using the available keys
function decodeToken(token) {
    const currentTime = new Date().getTime();

    let user = users.get(token)
    if (user && currentTime < user.expires)
        return { user_id: user._id, expires: user.expires };

    users.delete(token)
    return {}

}

// readKeyPairs();

module.exports = { encodeToken, decodeToken };
