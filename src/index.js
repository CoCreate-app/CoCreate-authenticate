const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Configuration
const tokenExpiration = 60; // Token expiration in minutes

// Array to store key pairs
const keyPairs = new Map();

// Map to store authenticated user payload and tokens
const sessions = new Map();

class CoCreateAuthenticate {
    constructor(crud) {
        this.wsManager = crud.wsManager
        this.crud = crud
    }

    // Create new RSA key pair
    createKeyPair() {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });

        let created = new Date(new Date().toISOString()).getTime()
        const keyPair = {
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
    deleteKeyPair(keyPair) {
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
    encodeToken(organization_id, user_id, clientId) {
        let keyPair = null
        const currentTime = new Date(new Date().toISOString()).getTime();
        for (let [key, value] of keyPairs) {
            if (currentTime > value.expires) {
                this.deleteKeyPair(value);
            } else {
                keyPair = value
            }
        }

        if (!keyPair) {
            keyPair = this.createKeyPair();
        }

        const token = jwt.sign({ user_id, clientId }, keyPair.privateKey, { algorithm: 'RS256', expiresIn: tokenExpiration * 60 });

        // TODO: session could have previous user ip and device information which we could use to comapre to current ip and device information 
        const session = { user_id, clientId, token, expires: currentTime + tokenExpiration * 60 * 1000 }
        sessions.set(clientId, session)

        this.crud.send({
            method: 'object.update',
            array: 'clients',
            object: {
                _id: clientId,
                session,
            },
            upsert: true,
            organization_id
        });

        return token;
    }

    // Verify and decode a token using the available keys
    async decodeToken(token, organization_id, clientId) {
        if (!token)
            return {}
        const currentTime = new Date().getTime();

        let session = sessions.get(clientId)
        if (!session || session.token !== token)
            session = await this.read(organization_id, clientId)

        // TODO: request must be made from same clientId and user_id that created the token
        if (session && currentTime < session.expires && session.token === token)
            return { user_id: session.user_id, expires: session.expires };

        sessions.delete(clientId)
        this.crud.send({
            method: 'object.update',
            array: 'clients',
            object: {
                _id: clientId,
                session: undefined
            },
            organization_id,
        });

        return {}

    }

    async read(organization_id, clientId) {
        const client = await this.crud.send({
            method: 'object.read',
            array: 'clients',
            object: {
                _id: clientId
            },
            organization_id,
        });

        if (client.object && client.object.length) {
            sessions.set(clientId, client.object[0].session)
        }

        return client.object[0].session
    }

}

module.exports = CoCreateAuthenticate;
