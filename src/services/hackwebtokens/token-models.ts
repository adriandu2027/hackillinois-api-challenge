// interface for data sent to /encode and payload returned from /decode
export interface EncodingDecodedData {
    user: string;
    data: unknown; // any JSON object
}

// interface for response from /encode
export interface EncodedData {
    token: string;
    context: {
        tokenId: string; // to retreive secret key later
    };
}

// interface for data sent to /decode
export interface DecodingData {
    token: string;
    context: {
        tokenId: string; // used to retreive secret key from DB
    };
}

// interface for storing the encryption keys (secretKey and IV) in the DB
export interface HackWebTokenData {
    secretKey: string; // secret key in hex format
    iv: string; // intialization vector in hex format
    tokenId: string; // unique token ID (secret key and iv are random)
}
