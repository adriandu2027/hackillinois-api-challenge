import { Router, Request, Response } from 'express';
import { encodeHackWebToken, decodeHackWebToken } from './token-lib';
import { EncodingDecodedData, DecodingData, EncodedData } from './token-models';

// Define constants for HTTP status codes (to pass linter)
const HTTP_OK = 200;
const HTTP_INTERNAL_SERVER_ERROR = 500;

const tokenRouter = Router();

/**
 * @api {post} /token/encode Encode User Data into a Token
 * @apiGroup Token
 * @apiDescription This endpoint takes user data and encodes it into a token using AES-256 encryption. The response includes the token and the context (which contains the unique token ID used for decryption).
 *
 * @apiParam {String} user The user's identifier.
 * @apiParam {Object} data The data to be encoded into the token.
 *
 * @apiSuccess (200: Success) {String} token The encrypted token containing the encoded user data.
 * @apiSuccess (200: Success) {Object} context Additional context that includes the `tokenId` used for decryption.
 *
 * @apiSuccessExample {json} Example Success Response:
 *  HTTP/1.1 200 OK
 *  {
 *      "token": "encrypted-token-string",
 *      "context": {
 *          "tokenId": "unique-token-id"
 *      }
 *  }
 *
 * @apiError (500: Internal Server Error) Failed to encode token due to server issues.
 * 
 * @apiErrorExample {json} Error Response:
 *  HTTP/1.1 500 Internal Server Error
 *  {
 *      "error": "Failed to encode token"
 *  }
 */
tokenRouter.post('/encode', async (req: Request, res: Response) => {
    const data: EncodingDecodedData = req.body as EncodingDecodedData;

    try {
        const response: EncodedData = await encodeHackWebToken(data);
        return res.status(HTTP_OK).json(response);
    } catch (error) {
        console.error('Encoding error:', error);
        return res.status(HTTP_INTERNAL_SERVER_ERROR).json({ error: 'Failed to encode token' });
    }
});


/**
 * @api {post} /token/decode Decode a Token to Reveal User Data
 * @apiGroup Token
 * @apiDescription This endpoint decodes a previously encoded token, revealing the user data associated with the token. It requires both the token and the tokenId (from the context) to perform decryption.
 *
 * @apiParam {String} token The encrypted token to be decoded.
 * @apiParam {Object} context The context object containing the `tokenId` used for decrypting the token.
 *
 * @apiSuccess (200: Success) {String} user The user's identifier extracted from the decoded token.
 * @apiSuccess (200: Success) {Object} data The data associated with the user that was decoded from the token.
 *
 * @apiSuccessExample {json} Example Success Response:
 *  HTTP/1.1 200 OK
 *  {
 *      "user": "testUser",
 *      "data": {
 *          "key": "value"
 *      }
 *  }
 *
 * @apiError (500: Internal Server Error) Failed to decode token, server ran into issue.
 * 
 * @apiErrorExample {json} Error Response:
 *  HTTP/1.1 500 Internal Server Error
 *  {
 *      "error": "Failed to decode token"
 *  }
 */
tokenRouter.post('/decode', async (req: Request, res: Response) => {
    const { token, context }: DecodingData = req.body as DecodingData;

    try {
        const decodedData = await decodeHackWebToken(token, context.tokenId);
        return res.status(HTTP_OK).json(decodedData);
    } catch (error) {
        console.error('Decoding error:', error);
        return res.status(HTTP_INTERNAL_SERVER_ERROR).json({ error: 'Failed to decode token' });
    }
});

export default tokenRouter;
