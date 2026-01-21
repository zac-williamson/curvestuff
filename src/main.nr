use bignum::BigNum;
use bignum::params::{BigNumParams};
use bignum::bignum::evaluate_quadratic_expression;
use bigcurve::{BigCurve, BigCurveParams, scalar_field::ScalarField, scalar_field::ScalarField::from_bignum as foo};
pub use bignum::derive_bignum;
pub use bigcurve::derive_curve_impl;

global TWO_POWER_120: Field = 1329227995784915872903807060280344576;

global Secp192r1_Fq_PARAMS: BigNumParams<2, 192> = BigNumParams::new(
    true,
    [0xfffffffffffffeffffffffffffffff, 0xffffffffffffffffff],
    [0x100000000000000010, 0x10000000000000000000]
);

global Secp192r1_Fr_PARAMS: BigNumParams<2, 192> = BigNumParams::new(
    true,
    [0xffffff99def836146bc9b1b4d22831, 0xffffffffffffffffff],
    [0x662107c9eb94364e4b2dd7cf2, 0x10000000000000000000]
);


#[derive_bignum(2, 192, quote {Secp192r1_Fq_PARAMS})]
pub struct Secp192r1_Fq {
    limbs: [u128; 2],
}

#[derive_bignum(2, 192, quote {Secp192r1_Fr_PARAMS})]
pub struct Secp192r1_Fr {
    limbs: [u128; 2],
}



pub use bignum::{BLS12_377_Fq, BLS12_377_Fr};

pub global CURVE_192_SCALAR_SLICES: u32 = 38;

pub global CURVE_192_PARAMS: BigCurveParams<Secp192r1_Fq> = BigCurveParams {
    a: Secp192r1_Fq{ limbs: [0xfffffffffffffefffffffffffffffc, 0xffffffffffffffffff] },
    b: Secp192r1_Fq{ limbs: [0xa7e9ab72243049feb8deecc146b9b1, 0x64210519e59c80e70f] },
    offset_generator: [
        Secp192r1_Fq{ limbs:[
            0xba342dd2e8a57e30e4fab3aac114b2,
            0x6e7346ab4fea7f55a1f08939754a50,
        ]},
        Secp192r1_Fq{ limbs:[
            0x8a796bd31648b17a897fce57b28356,
            0x2e1d2547bb3228e76b01175312545b,
        ]},
    ],
    offset_generator_final: [
        Secp192r1_Fq{ limbs: [
            0x671498ee656f13e9b769355538d6a5,
            0x50f93aaeb8c9ffbd231d89d655a66e,
        ]},
        Secp192r1_Fq{ limbs: [
            0x7e1116c8a65727559685d7c70063ff,
            0xf16bb13f725cac296ddbd1bd54515c,
        ]},
    ],
    one: [
        Secp192r1_Fq{ limbs: [
0xbf20eb43a18800f4ff0afd82ff1012, 0x188da80eb03090f67c        ]},
        Secp192r1_Fq{ limbs: [
0x1011ed6b24cdd573f977a11e794811, 0x7192b95ffc8da7863        ]},
    ],
};

pub type Curve_192Scalar = ScalarField<CURVE_192_SCALAR_SLICES>;

#[derive_curve_impl(quote { Secp192r1_Fq }, quote { CURVE_192_PARAMS })]
pub struct Curve_192 {
    pub x: Secp192r1_Fq,
    pub y: Secp192r1_Fq,
    pub is_infinity: bool,
}
   

pub fn ecdsa_ver(sig: [[u128; 2]; 2], pk: [[u128; 2]; 2], hashed: [u8; 20]) {
    let mut extended_hadhed = [0; 24];
    for i in 0..20{
        extended_hadhed[i+4] = hashed[i];
    }

    let h: Secp192r1_Fr= Secp192r1_Fr::from_be_bytes(extended_hadhed);

    let r: Secp192r1_Fr = Secp192r1_Fr{
        limbs: sig[0]
    };

    let s: Secp192r1_Fr = Secp192r1_Fr{
        limbs: sig[1]
    };

    let s_inv = BigNum::one() / s;
    let hs  = s_inv * h;
    let rs = s_inv * r;

    // scalars[0] = hs.limbs[0] + hs.limbs[1] * TWO_POWER_120;
    // scalars[1] = rs.limbs[0] + rs.limbs[1] * TWO_POWER_120;
    let scalar0 = Curve_192Scalar::from_bignum(hs);
    let scalar1 = Curve_192Scalar::from_bignum(rs);

    let pk = Curve_192::from_coordinates(Secp192r1_Fq{ limbs: [pk[0][0], pk[0][1]]}, Secp192r1_Fq{ limbs: [pk[1][0], pk[1][1]]}, false);

    let r_point: Curve_192 = Curve_192::evaluate_linear_expression([Curve_192::one(), pk], [scalar0, scalar1], []);

    assert(r_point.x.limbs[0] == sig[0][0], "");
    assert(r_point.x.limbs[1] == sig[0][1], "");

}   



#[test]
fn test_ecdsa(){
    ecdsa_ver(
    [
            [0x1a9431f728880790e1254cadb1303a, 0xd11b917a7ca8ca1aa],
            [0x66feb65c55b5a50bf21d5b2ef573dc, 0x85a546b59fab76c141]
        ],
    [
            [0xd30c77054172f04148fe39091495a0, 0x170b554d3623c7b19c],
            [0x252a3b0920adb0992cb830f93ae0c4, 0xcd20ab289cdefc0e83]
        ],
[124, 28, 16, 40, 230, 60, 31, 188, 223, 45, 206, 163, 158, 209, 112, 220, 125, 117, 74, 213]
    );
}

