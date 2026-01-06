export class Curve {
    F: any;
    d: any;
    Base: Point;

    constructor(F: any) {
        this.F = F;
        this.d = F.e("3021");
        this.Base = new Point(
            F.e("717051916204163000937139483451426116831771857428389560441264442629694842243"),
            F.e("882565546457454111605105352482086902132191855952243170543452705048019814192"),
            this
        );
    }

    zero(): Point {
        return new Point(this.F.zero, this.F.one, this);
    }
}

export class Point {
    x: any;
    y: any;
    curve: Curve;

    constructor(x: any, y: any, curve: Curve) {
        this.x = x;
        this.y = y;
        this.curve = curve;
    }

    add(p: Point): Point {
        const F = this.curve.F;
        const x1 = this.x;
        const y1 = this.y;
        const x2 = p.x;
        const y2 = p.y;
        const d = this.curve.d;

        const x1x2 = F.mul(x1, x2);
        const y1y2 = F.mul(y1, y2);
        const x1y2 = F.mul(x1, y2);
        const y1x2 = F.mul(y1, x2);
        const d_x1x2y1y2 = F.mul(d, F.mul(x1x2, y1y2));

        const x3 = F.div(F.add(x1y2, y1x2), F.add(F.one, d_x1x2y1y2));
        const y3 = F.div(F.add(y1y2, x1x2), F.sub(F.one, d_x1x2y1y2));

        return new Point(x3, y3, this.curve);
    }

    mul(s: bigint | string | number): Point {
        let n = BigInt(s);
        let res = this.curve.zero();
        let temp: Point = this;

        while (n > 0n) {
            if (n & 1n) {
                res = res.add(temp);
            }
            temp = temp.add(temp);
            n >>= 1n;
        }
        return res;
    }
}
