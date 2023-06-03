const jwt = require("jsonwebtoken")
const uid = require("@cocreate/uuid")

class CoCreateAuthenticate {
    /**
     * config structure 
     * https://www.npmjs.com/package/jsonwebtoken
     {
        key: 'xxxxxx', // any value
        options: {
            algorithm: "HS256",
            expiresIn: "30m",
            issuer: "issuer"
        }
     }
     **/


    constructor(config) {
        this.config = config
        this.config['key'] = uid.generate(40)
    }

    async generateToken({ user_id }) {
        try {
            const { key, options } = this.config
            const result = {
                token: jwt.sign({ user_id }, key, options),
            }
            return result.token;
        } catch (err) {
            return null
        }
    }

    async getUserId(req) {
        try {
            let { user_id } = await this.wsCheck(req)
            return user_id
        } catch (err) {
            return null
        }
    }

    getTokenFromCookie(cookie) {
        let token = null;
        if (cookie) {
            cookie.split(';').forEach((c) => {
                try {
                    var parts = c.split('=')
                    if (parts[0].trim() == 'token') {
                        token = decodeURI(parts[1].trim());
                    }
                } catch (err) {
                    console.log(err)
                }
            })
        }
        return token;
    }

    async wsCheck(req) {
        const headers = req.headers
        let token = headers['sec-websocket-protocol'];
        // let token = this.getTokenFromCookie(headers.cookie);
        // if (!token) {
        //     token = headers['sec-websocket-protocol'];
        // }

        let result = null;
        if (token && token !== 'null') {
            result = await this.verifiyToken(token);
        }

        return result;
    }

    async httpCheck(req) {

    }

    async verifiyToken(token) {
        try {
            let decoded = await jwt.verify(token, this.config.key)
            return decoded;
        } catch (err) {
            if (err.message === 'jwt expired') {
                console.log('Expired Token')
                return null
            } else if (err.message === 'invalid token') {
                console.log('Invalid Token')
                return null
            } else {
                console.log('Invalid token', token)
                return null;
            }
        }

    }
}

module.exports = CoCreateAuthenticate;