import * as crypto from 'crypto';
import { EncodingDecodedData, EncodedData, HackWebTokenData } from './token-models';
import { getModelForClass } from "@typegoose/typegoose";
import { HackWebTokenModel } from '../../database/token-db';

export const HackWebToken = getModelForClass(HackWebTokenModel);

// fn to store enrcyption data (secret key, iv, and tokenId) in the db
export async function storeEncryptionDataInDB(data: HackWebTokenData): Promise<void> {
    try {
        const tokenData = new HackWebToken();  // Create new document w/ db token model
        tokenData.tokenId = data.tokenId;
        tokenData.secretKey = data.secretKey;
        tokenData.iv = data.iv;
        await tokenData.save();  // Save doc to the database
    } catch (error) {
        console.error('Failed to store encryption data:', error);
        throw new Error('InternalError');
    }
}

// fn to encode input payload into a token
export async function encodeHackWebToken(data: EncodingDecodedData): Promise<EncodedData> {
    const jsonPayload = JSON.stringify(data);

    // generate random secret key using aes-256
    const secretKey = crypto.randomBytes(32);   // secret key is 32 bytes
    const iv = crypto.randomBytes(16);

    // create aes cipher corresponding our random key and iv
    const cipher = crypto.createCipheriv('aes-256-cbc', secretKey, iv);

    // encrypt payload
    let encrypted = cipher.update(jsonPayload, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    // generate unique token ID to store in db (so we can retreive iv and secret key for decryption)
    const tokenId = crypto.randomUUID();

    // store encrypion keys and token id in db
    const encryptionData: HackWebTokenData = {
        secretKey: secretKey.toString('hex'),
        iv: iv.toString('hex'),
        tokenId: tokenId
    };
    await storeEncryptionDataInDB(encryptionData);

    // return encoded payload w/ tokenId
    return {
        token: encrypted,
        context: {
            tokenId: tokenId
        }
    };
}

// fn to retrieve encryption data (secretKey, IV, and tokenId) from the database
export async function retrieveEncryptionDataFromDB(tokenId: string): Promise<HackWebTokenData | null> {
    try {
        const tokenData = await HackWebToken.findOne({ tokenId }).exec();  // find document by tokenId
        if (!tokenData) {
            throw new Error('Token encryption data not found');
        }
        return tokenData as HackWebTokenData;
    } catch (error) {
        console.error('Error retrieving token data:', error);
        throw new Error('Failed to retreive token data');
    }
}

// fn to decode the token
export async function decodeHackWebToken(token: string, tokenId: string): Promise<EncodingDecodedData> {
    // retreive encryption data from db using tokenId
    const encryptionData = await retrieveEncryptionDataFromDB(tokenId);
    if (!encryptionData) {
        throw new Error('token encryption data not found');
    }
    const { secretKey, iv } = encryptionData;

    // convert hex strings back to buffers (raw binary)
    const keyBuffer = Buffer.from(secretKey, 'hex');
    const ivBuffer = Buffer.from(iv, 'hex');

    // create the aes decipher
    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);

    // decyrpt the token
    let decrypted = decipher.update(token, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');

    // parse decrypted JSON back into object
    const decodedData: EncodingDecodedData = JSON.parse(decrypted);

    return decodedData;
}
