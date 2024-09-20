import { Router, Request, Response } from 'express';
import { encodeHackWebToken, decodeHackWebToken } from './token-lib';
import { EncodingDecodedData, DecodingData, EncodedData } from './token-models';

const tokenRouter = Router();

// encode user data into a token
tokenRouter.post('/encode', async (req: Request, res: Response) => {
    const data: EncodingDecodedData = req.body as EncodingDecodedData;

    try {
        const response: EncodedData = await encodeHackWebToken(data);
        return res.status(200).json(response);
    } catch (error) {
        console.error('Encoding error:', error);
        return res.status(500).json({ error: 'Failed to encode token' });
    }
});

// decode a token to reveal user data
tokenRouter.post('/decode', async (req: Request, res: Response) => {
    const { token, context }: DecodingData = req.body as DecodingData;

    try {
        const decodedData = await decodeHackWebToken(token, context.tokenId);
        return res.status(200).json(decodedData);
    } catch (error) {
        console.error('Decoding error:', error);
        return res.status(500).json({ error: 'Failed to decode token' });
    }
});

export default tokenRouter;
