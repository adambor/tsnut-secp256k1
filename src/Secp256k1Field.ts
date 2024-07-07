import {IField, IPoint, IScalar} from "tsnut";
import * as secp256k1 from "tiny-secp256k1";
import {createHash} from "node:crypto";

export class Secp256k1Scalar implements IScalar<Secp256k1Field> {

    field: Secp256k1Field;
    data: Uint8Array;

    constructor(field: Secp256k1Field, data: Uint8Array) {
        this.field = field;
        this.data = data;
    }

    getField(): Secp256k1Field {
        return this.field;
    }
    sign(point: Secp256k1Point): Secp256k1Point {
        return point.mul(this);
    }
    toPoint(): Secp256k1Point {
        return new Secp256k1Point(this.field, secp256k1.pointFromScalar(this.data, true));
    }
    isMember(): boolean {
        return secp256k1.pointFromScalar(this.data, true)!==null;
    }
    toHex(): string {
        return Buffer.from(this.data).toString("hex");
    }

}

export class Secp256k1Point implements IPoint<Secp256k1Field> {

    field: Secp256k1Field;
    data: Uint8Array;

    constructor(field: Secp256k1Field, data: Uint8Array) {
        this.field = field;
        this.data = data;
    }

    getField(): Secp256k1Field {
        return this.field;
    }
    add(b: Secp256k1Point): Secp256k1Point {
        return new Secp256k1Point(this.field, secp256k1.pointAdd(this.data, b.data, true));
    }
    mul(s: Secp256k1Scalar): Secp256k1Point {
        return new Secp256k1Point(this.field, secp256k1.pointMultiply(this.data, s.data, true));
    }
    equals(b: Secp256k1Point): boolean {
        return this.data.every((value, index) => b.data[index] === value);
    }
    isMember(): boolean {
        return secp256k1.isPoint(this.data);
    }
    toHex(): string {
        return Buffer.from(this.data).toString("hex");
    }

}

const DOMAIN_SEPARATOR = Buffer.from("Secp256k1_HashToCurve_Cashu_");

export class Secp256k1Field implements IField<Secp256k1Scalar, Secp256k1Point> {

    hashToField(bytes: Buffer): Secp256k1Point {
        const msgHash = createHash("sha256").update(Buffer.concat([DOMAIN_SEPARATOR, bytes])).digest();
        for(let i=0;i<0xFFFFFFFF;i++) {
            const counterBuffer = Buffer.alloc(4);
            counterBuffer.writeUint32LE(i, 0);
            const hash = createHash("sha256").update(Buffer.concat([msgHash, counterBuffer])).digest();
            const point = new Secp256k1Point(this, Buffer.concat([Buffer.from([0x02]), hash]));
            if(point.isMember()) return point;
        }
        return null;
    }

    hexToPoint(hexString: string): Secp256k1Point {
        return new Secp256k1Point(this, Buffer.from(hexString, "hex"));
    }

    hexToScalar(hexString: string): Secp256k1Scalar {
        return new Secp256k1Scalar(this, Buffer.from(hexString, "hex"));
    }

    isValidPoint(hexString: string): boolean {
        return this.hexToPoint(hexString).isMember();
    }

    isValidScalar(hexString: string): boolean {
        return this.hexToScalar(hexString).isMember();
    }

}
