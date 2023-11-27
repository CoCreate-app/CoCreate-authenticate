const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('@cocreate/utils');

// Configuration
const tokenExpiration = 60; // Token expiration in minutes

// Array to store key pairs
const keyPairs = new Map();

// Map to store authenticated user payload and tokens
const clients = new Map();

// crud.listen('object.delete', function (data) {
//     if (data.object && data.object[0] && data.object[0].type === 'RSA')
//         keyPairs.delete(data.object[0]._id);
// });

// Create new RSA key pair
function createKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });

    let created = new Date(new Date().toISOString()).getTime()
    const keyPair = {
        _id: ObjectId().toString(),
        // type: "RSA",
        privateKey,
        publicKey,
        created,
        expires: created + tokenExpiration * 60 * 1000, // Convert minutes to milliseconds
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

// Delete new RSA key pair
function deleteKeyPair(keyPair) {
    keyPairs.delete(keyPair._id)
    // crud.send({
    //     method: 'object.delete',
    //     array: 'keys',
    //     object: {
    //         _id: keyPair._id,
    //         type: 'RSA'
    //     },
    //     organization_id: process.env.organization_id,
    // });
}

// Function to sign a new token using the newest keyPair
function encodeToken(data) {
    let keyPair = null
    const currentTime = new Date(new Date().toISOString()).getTime();
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
    const token = jwt.sign({ user_id: data.user_id, clientId: data.clientId }, keyPair.privateKey, { algorithm: 'RS256', expiresIn: tokenExpiration * 60 });

    const payload = { _id: data.clientId, user_id: data.user_id, clientId: data.clientId, token, expires: currentTime + tokenExpiration * 60 * 1000 }

    clients.set(data.clientId, payload)

    // TODO: add to organization tokens array
    crud.send({
        method: 'object.update',
        array: 'tokens',
        object: {
            ...payload,
        },
        upsert: true,
        organization_id: data.organization_id,
    });

    return token;
}

// Verify and decode a token using the available keys
// TODO: request must be made from same clientId and user_id that created the token
async function decodeToken(token, organization_id) {
    const currentTime = new Date().getTime();

    let client = clients.get(token)
    if (!client)
        client = await read(token, organization_id, user_id, clientId)

    if (client && currentTime < client.session.expires)
        return { user_id: user._id, expires: user.expires };

    // TODO: read user key for tokens

    clients.delete(token)
    crud.send({
        method: 'object.delete',
        array: 'tokens',
        object: {
            _id: clientId
        },
        organization_id,
    });

    return {}

}

// Function to read token from the database
function read(token, organization_id, user_id, clientId) {
    const keys = crud.send({
        method: 'object.read',
        array: 'clients',
        object: {
            _id: clientId
        },
        organization_id,
    });

    // Add retrieved key pairs to the keyPairs array
    if (keys.object && keys.object.length) {
        keys.object[0].user_id = user_id
        clients.set(token, keys.object[0]._id)
    }

    return keys.object[0]
}

function deleteToken(token, organization_id, user_id, clientId) {
    clients.delete(token)
    crud.send({
        method: 'object.delete',
        array: 'tokens',
        object: {
            _id: clientId
        },
        organization_id,
    });
}


module.exports = { encodeToken, decodeToken };
