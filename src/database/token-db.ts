import { prop } from "@typegoose/typegoose";

export class HackWebTokenModel {
    @prop({ required: true })
    public tokenId!: string;

    @prop({ required: true })
    public secretKey!: string;

    @prop({ required: true })
    public iv!: string;
}
