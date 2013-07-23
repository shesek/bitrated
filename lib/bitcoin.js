module.exports = (function(module,window){
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
;
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)
;
// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
  this.i = 0;
  this.j = 0;
  this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
  var i, j, t;
  for(i = 0; i < 256; ++i)
    this.S[i] = i;
  j = 0;
  for(i = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  this.i = 0;
  this.j = 0;
}

function ARC4next() {
  var t;
  this.i = (this.i + 1) & 255;
  this.j = (this.j + this.S[this.i]) & 255;
  t = this.S[this.i];
  this.S[this.i] = this.S[this.j];
  this.S[this.j] = t;
  return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
  return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;
;
// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

var rng_state;
var rng_pool;
var rng_pptr;

// Mix in a 32-bit integer into the pool
function rng_seed_int(x) {
  rng_pool[rng_pptr++] ^= x & 255;
  rng_pool[rng_pptr++] ^= (x >> 8) & 255;
  rng_pool[rng_pptr++] ^= (x >> 16) & 255;
  rng_pool[rng_pptr++] ^= (x >> 24) & 255;
  if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

// Mix in the current time (w/milliseconds) into the pool
function rng_seed_time() {
  rng_seed_int(new Date().getTime());
}

// Initialize the pool with junk if needed.
if(rng_pool == null) {
  rng_pool = new Array();
  rng_pptr = 0;
  var t;
  if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
    // Extract entropy (256 bits) from NS4 RNG if available
    var z = window.crypto.random(32);
    for(t = 0; t < z.length; ++t)
      rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
  }  
  while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
    t = Math.floor(65536 * Math.random());
    rng_pool[rng_pptr++] = t >>> 8;
    rng_pool[rng_pptr++] = t & 255;
  }
  rng_pptr = 0;
  rng_seed_time();
  //rng_seed_int(window.screenX);
  //rng_seed_int(window.screenY);
}

function rng_get_byte() {
  if(rng_state == null) {
    rng_seed_time();
    rng_state = prng_newstate();
    rng_state.init(rng_pool);
    for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
      rng_pool[rng_pptr] = 0;
    rng_pptr = 0;
    //rng_pool = null;
  }
  // TODO: allow reseeding after first request
  return rng_state.next();
}

function rng_get_bytes(ba) {
  var i;
  for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;
;
// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// Only Fp curves implemented for now

// Requires jsbn.js and jsbn2.js

// ----------------
// ECFieldElementFp

// constructor
function ECFieldElementFp(q,x) {
    this.x = x;
    // TODO if(x.compareTo(q) >= 0) error
    this.q = q;
}

function feFpEquals(other) {
    if(other == this) return true;
    return (this.q.equals(other.q) && this.x.equals(other.x));
}

function feFpToBigInteger() {
    return this.x;
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}

function feFpAdd(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}

function feFpSubtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}

function feFpMultiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}

function feFpDivide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}

ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;

// ----------------
// ECPointFp

// constructor
function ECPointFp(curve,x,y,z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    // Projective coordinates: either zinv == null or z * zinv == 1
    // z and zinv are just BigIntegers, not fieldElements
    if(z == null) {
      this.z = BigInteger.ONE;
    }
    else {
      this.z = z;
    }
    this.zinv = null;
    //TODO: compression flag
}

function pointFpGetX() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpGetY() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpEquals(other) {
    if(other == this) return true;
    if(this.isInfinity()) return other.isInfinity();
    if(other.isInfinity()) return this.isInfinity();
    var u, v;
    // u = Y2 * Z1 - Y1 * Z2
    u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
    if(!u.equals(BigInteger.ZERO)) return false;
    // v = X2 * Z1 - X1 * Z2
    v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
    return v.equals(BigInteger.ZERO);
}

function pointFpIsInfinity() {
    if((this.x == null) && (this.y == null)) return true;
    return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}

function pointFpNegate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}

function pointFpAdd(b) {
    if(this.isInfinity()) return b;
    if(b.isInfinity()) return this;

    // u = Y2 * Z1 - Y1 * Z2
    var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
    // v = X2 * Z1 - X1 * Z2
    var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

    if(BigInteger.ZERO.equals(v)) {
        if(BigInteger.ZERO.equals(u)) {
            return this.twice(); // this == b, so double
        }
	return this.curve.getInfinity(); // this = -b, so infinity
    }

    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();
    var x2 = b.x.toBigInteger();
    var y2 = b.y.toBigInteger();

    var v2 = v.square();
    var v3 = v2.multiply(v);
    var x1v2 = x1.multiply(v2);
    var zu2 = u.square().multiply(this.z);

    // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
    var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
    // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
    var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
    // z3 = v^3 * z1 * z2
    var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpTwice() {
    if(this.isInfinity()) return this;
    if(this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

    // TODO: optimized handling of constants
    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();

    var y1z1 = y1.multiply(this.z);
    var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
    var a = this.curve.a.toBigInteger();

    // w = 3 * x1^2 + a * z1^2
    var w = x1.square().multiply(THREE);
    if(!BigInteger.ZERO.equals(a)) {
      w = w.add(this.z.square().multiply(a));
    }
    w = w.mod(this.curve.q);
    // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
    var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
    // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
    var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
    // z3 = 8 * (y1 * z1)^3
    var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

// Simple NAF (Non-Adjacent Form) multiplication algorithm
// TODO: modularize the multiplication algorithm
function pointFpMultiply(k) {
    if(this.isInfinity()) return this;
    if(k.signum() == 0) return this.curve.getInfinity();

    var e = k;
    var h = e.multiply(new BigInteger("3"));

    var neg = this.negate();
    var R = this;

    var i;
    for(i = h.bitLength() - 2; i > 0; --i) {
	R = R.twice();

	var hBit = h.testBit(i);
	var eBit = e.testBit(i);

	if (hBit != eBit) {
	    R = R.add(hBit ? this : neg);
	}
    }

    return R;
}

// Compute this*j + x*k (simultaneous multiplication)
function pointFpMultiplyTwo(j,x,k) {
  var i;
  if(j.bitLength() > k.bitLength())
    i = j.bitLength() - 1;
  else
    i = k.bitLength() - 1;

  var R = this.curve.getInfinity();
  var both = this.add(x);
  while(i >= 0) {
    R = R.twice();
    if(j.testBit(i)) {
      if(k.testBit(i)) {
        R = R.add(both);
      }
      else {
        R = R.add(this);
      }
    }
    else {
      if(k.testBit(i)) {
        R = R.add(x);
      }
    }
    --i;
  }

  return R;
}

ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;

// ----------------
// ECCurveFp

// constructor
function ECCurveFp(q,a,b) {
    this.q = q;
    this.a = this.fromBigInteger(a);
    this.b = this.fromBigInteger(b);
    this.infinity = new ECPointFp(this, null, null);
}

function curveFpGetQ() {
    return this.q;
}

function curveFpGetA() {
    return this.a;
}

function curveFpGetB() {
    return this.b;
}

function curveFpEquals(other) {
    if(other == this) return true;
    return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
}

function curveFpGetInfinity() {
    return this.infinity;
}

function curveFpFromBigInteger(x) {
    return new ECFieldElementFp(this.q, x);
}

// for now, work with hex strings because they're easier in JS
function curveFpDecodePointHex(s) {
    switch(parseInt(s.substr(0,2), 16)) { // first byte
    case 0:
	return this.infinity;
    case 2:
    case 3:
	// point compression not supported yet
	return null;
    case 4:
    case 6:
    case 7:
	var len = (s.length - 2) / 2;
	var xHex = s.substr(2, len);
	var yHex = s.substr(len+2, len);

	return new ECPointFp(this,
			     this.fromBigInteger(new BigInteger(xHex, 16)),
			     this.fromBigInteger(new BigInteger(yHex, 16)));

    default: // unsupported
	return null;
    }
}

ECCurveFp.prototype.getQ = curveFpGetQ;
ECCurveFp.prototype.getA = curveFpGetA;
ECCurveFp.prototype.getB = curveFpGetB;
ECCurveFp.prototype.equals = curveFpEquals;
ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;
;
// Named EC curves

// Requires ec.js, jsbn.js, and jsbn2.js

// ----------------
// X9ECParameters

// constructor
function X9ECParameters(curve,g,n,h) {
    this.curve = curve;
    this.g = g;
    this.n = n;
    this.h = h;
}

function x9getCurve() {
    return this.curve;
}

function x9getG() {
    return this.g;
}

function x9getN() {
    return this.n;
}

function x9getH() {
    return this.h;
}

X9ECParameters.prototype.getCurve = x9getCurve;
X9ECParameters.prototype.getG = x9getG;
X9ECParameters.prototype.getN = x9getN;
X9ECParameters.prototype.getH = x9getH;

// ----------------
// SECNamedCurves

function fromHex(s) { return new BigInteger(s, 16); }

function secp128r1() {
    // p = 2^128 - 2^97 - 1
    var p = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");
    var b = fromHex("E87579C11079F43DD824993C2CEE5ED3");
    //byte[] S = Hex.decode("000E0D4D696E6768756151750CC03A4473D03679");
    var n = fromHex("FFFFFFFE0000000075A30D1B9038A115");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "161FF7528B899B2D0C28607CA52C5B86"
		+ "CF5AC8395BAFEB13C02DA292DDED7A83");
    return new X9ECParameters(curve, G, n, h);
}

function secp160k1() {
    // p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
    var a = BigInteger.ZERO;
    var b = fromHex("7");
    //byte[] S = null;
    var n = fromHex("0100000000000000000001B8FA16DFAB9ACA16B6B3");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"
                + "938CF935318FDCED6BC28286531733C3F03C4FEE");
    return new X9ECParameters(curve, G, n, h);
}

function secp160r1() {
    // p = 2^160 - 2^31 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");
    var b = fromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
    //byte[] S = Hex.decode("1053CDE42C14D696E67687561517533BF3F83345");
    var n = fromHex("0100000000000000000001F4C8F927AED3CA752257");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
		+ "4A96B5688EF573284664698968C38BB913CBFC82"
		+ "23A628553168947D59DCC912042351377AC5FB32");
    return new X9ECParameters(curve, G, n, h);
}

function secp192k1() {
    // p = 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
    var a = BigInteger.ZERO;
    var b = fromHex("3");
    //byte[] S = null;
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
                + "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D");
    return new X9ECParameters(curve, G, n, h);
}

function secp192r1() {
    // p = 2^192 - 2^64 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
    var b = fromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
    //byte[] S = Hex.decode("3045AE6FC8422F64ED579528D38120EAE12196D5");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
                + "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
    return new X9ECParameters(curve, G, n, h);
}

function secp224r1() {
    // p = 2^224 - 2^96 + 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    var b = fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    //byte[] S = Hex.decode("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
    return new X9ECParameters(curve, G, n, h);
}

function secp256k1() {
    // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    var a = BigInteger.ZERO;
    var b = fromHex("7");
    //byte[] S = null;
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	            + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    return new X9ECParameters(curve, G, n, h);
}

function secp256r1() {
    // p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
    var p = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    var b = fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    //byte[] S = Hex.decode("C49D360886E704936A6678E1139D26B7819F7E90");
    var n = fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
		+ "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    return new X9ECParameters(curve, G, n, h);
}

// TODO: make this into a proper hashtable
function getSECCurveByName(name) {
    if(name == "secp128r1") return secp128r1();
    if(name == "secp160k1") return secp160k1();
    if(name == "secp160r1") return secp160r1();
    if(name == "secp192k1") return secp192k1();
    if(name == "secp192r1") return secp192r1();
    if(name == "secp224r1") return secp224r1();
    if(name == "secp256k1") return secp256k1();
    if(name == "secp256r1") return secp256r1();
    return null;
}
;
/*!
 * Crypto-JS v2.0.0
 * http://code.google.com/p/crypto-js/
 * Copyright (c) 2009, Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
(function(){

var base64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Global Crypto object
var Crypto = window.Crypto = {};

// Crypto utilities
var util = Crypto.util = {

	// Bit-wise rotate left
	rotl: function (n, b) {
		return (n << b) | (n >>> (32 - b));
	},

	// Bit-wise rotate right
	rotr: function (n, b) {
		return (n << (32 - b)) | (n >>> b);
	},

	// Swap big-endian to little-endian and vice versa
	endian: function (n) {

		// If number given, swap endian
		if (n.constructor == Number) {
			return util.rotl(n,  8) & 0x00FF00FF |
			       util.rotl(n, 24) & 0xFF00FF00;
		}

		// Else, assume array and swap all items
		for (var i = 0; i < n.length; i++)
			n[i] = util.endian(n[i]);
		return n;

	},

	// Generate an array of any length of random bytes
	randomBytes: function (n) {
		for (var bytes = []; n > 0; n--)
			bytes.push(Math.floor(Math.random() * 256));
		return bytes;
	},

	// Convert a byte array to big-endian 32-bit words
	bytesToWords: function (bytes) {
		for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
			words[b >>> 5] |= bytes[i] << (24 - b % 32);
		return words;
	},

	// Convert big-endian 32-bit words to a byte array
	wordsToBytes: function (words) {
		for (var bytes = [], b = 0; b < words.length * 32; b += 8)
			bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
		return bytes;
	},

	// Convert a byte array to a hex string
	bytesToHex: function (bytes) {
		for (var hex = [], i = 0; i < bytes.length; i++) {
			hex.push((bytes[i] >>> 4).toString(16));
			hex.push((bytes[i] & 0xF).toString(16));
		}
		return hex.join("");
	},

	// Convert a hex string to a byte array
	hexToBytes: function (hex) {
		for (var bytes = [], c = 0; c < hex.length; c += 2)
			bytes.push(parseInt(hex.substr(c, 2), 16));
		return bytes;
	},

	// Convert a byte array to a base-64 string
	bytesToBase64: function (bytes) {

		// Use browser-native function if it exists
		if (typeof btoa == "function") return btoa(Binary.bytesToString(bytes));

		for(var base64 = [], i = 0; i < bytes.length; i += 3) {
			var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
			for (var j = 0; j < 4; j++) {
				if (i * 8 + j * 6 <= bytes.length * 8)
					base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
				else base64.push("=");
			}
		}

		return base64.join("");

	},

	// Convert a base-64 string to a byte array
	base64ToBytes: function (base64) {

		// Use browser-native function if it exists
		if (typeof atob == "function") return Binary.stringToBytes(atob(base64));

		// Remove non-base-64 characters
		base64 = base64.replace(/[^A-Z0-9+\/]/ig, "");

		for (var bytes = [], i = 0, imod4 = 0; i < base64.length; imod4 = ++i % 4) {
			if (imod4 == 0) continue;
			bytes.push(((base64map.indexOf(base64.charAt(i - 1)) & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2)) |
			           (base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2)));
		}

		return bytes;

	}

};

// Crypto mode namespace
Crypto.mode = {};

// Crypto character encodings
var charenc = Crypto.charenc = {};

// UTF-8 encoding
var UTF8 = charenc.UTF8 = {

	// Convert a string to a byte array
	stringToBytes: function (str) {
		return Binary.stringToBytes(unescape(encodeURIComponent(str)));
	},

	// Convert a byte array to a string
	bytesToString: function (bytes) {
		return decodeURIComponent(escape(Binary.bytesToString(bytes)));
	}

};

// Binary encoding
var Binary = charenc.Binary = {

	// Convert a string to a byte array
	stringToBytes: function (str) {
		for (var bytes = [], i = 0; i < str.length; i++)
			bytes.push(str.charCodeAt(i));
		return bytes;
	},

	// Convert a byte array to a string
	bytesToString: function (bytes) {
		for (var str = [], i = 0; i < bytes.length; i++)
			str.push(String.fromCharCode(bytes[i]));
		return str.join("");
	}

};

})();
;
/*!
 * Crypto-JS v2.0.0
 * http://code.google.com/p/crypto-js/
 * Copyright (c) 2009, Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
(function(){

// Shortcuts
var C = Crypto,
    util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8,
    Binary = charenc.Binary;

// Constants
var K = [ 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
          0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
          0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
          0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
          0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
          0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
          0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
          0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
          0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
          0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
          0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
          0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
          0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
          0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
          0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
          0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2 ];

// Public API
var SHA256 = C.SHA256 = function (message, options) {
	var digestbytes = util.wordsToBytes(SHA256._sha256(message));
	return options && options.asBytes ? digestbytes :
	       options && options.asString ? Binary.bytesToString(digestbytes) :
	       util.bytesToHex(digestbytes);
};

// The core
SHA256._sha256 = function (message) {

	// Convert to byte array
	if (message.constructor == String) message = UTF8.stringToBytes(message);
	/* else, assume byte array already */

	var m = util.bytesToWords(message),
	    l = message.length * 8,
	    H = [ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	          0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 ],
	    w = [],
	    a, b, c, d, e, f, g, h, i, j,
	    t1, t2;

	// Padding
	m[l >> 5] |= 0x80 << (24 - l % 32);
	m[((l + 64 >> 9) << 4) + 15] = l;

	for (var i = 0; i < m.length; i += 16) {

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		for (var j = 0; j < 64; j++) {

			if (j < 16) w[j] = m[j + i];
			else {

				var gamma0x = w[j - 15],
				    gamma1x = w[j - 2],
				    gamma0  = ((gamma0x << 25) | (gamma0x >>>  7)) ^
				              ((gamma0x << 14) | (gamma0x >>> 18)) ^
				               (gamma0x >>> 3),
				    gamma1  = ((gamma1x <<  15) | (gamma1x >>> 17)) ^
				              ((gamma1x <<  13) | (gamma1x >>> 19)) ^
				               (gamma1x >>> 10);

				w[j] = gamma0 + (w[j - 7] >>> 0) +
				       gamma1 + (w[j - 16] >>> 0);

			}

			var ch  = e & f ^ ~e & g,
			    maj = a & b ^ a & c ^ b & c,
			    sigma0 = ((a << 30) | (a >>>  2)) ^
			             ((a << 19) | (a >>> 13)) ^
			             ((a << 10) | (a >>> 22)),
			    sigma1 = ((e << 26) | (e >>>  6)) ^
			             ((e << 21) | (e >>> 11)) ^
			             ((e <<  7) | (e >>> 25));


			t1 = (h >>> 0) + sigma1 + ch + (K[j]) + (w[j] >>> 0);
			t2 = sigma0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;

		}

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;

	}

	return H;

};

// Package private blocksize
SHA256._blocksize = 16;

})();
;
/*!
 * Crypto-JS v2.0.0
 * http://code.google.com/p/crypto-js/
 * Copyright (c) 2009, Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 *
 * A JavaScript implementation of the RIPEMD-160 Algorithm
 * Version 2.2 Copyright Jeremy Lin, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 * Also http://www.ocf.berkeley.edu/~jjlin/jsotp/
 * Ported to Crypto-JS by Stefan Thomas.
 */

(function () {
	// Shortcuts
	var C = Crypto,
    util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8,
    Binary = charenc.Binary;

	// Convert a byte array to little-endian 32-bit words
	util.bytesToLWords = function (bytes) {

		var output = Array(bytes.length >> 2);
		for (var i = 0; i < output.length; i++)
			output[i] = 0;
		for (var i = 0; i < bytes.length * 8; i += 8)
			output[i>>5] |= (bytes[i / 8] & 0xFF) << (i%32);
		return output;
	};

	// Convert little-endian 32-bit words to a byte array
	util.lWordsToBytes = function (words) {
		var output = [];
		for (var i = 0; i < words.length * 32; i += 8)
			output.push((words[i>>5] >>> (i % 32)) & 0xff);
		return output;
	};

	// Public API
	var RIPEMD160 = C.RIPEMD160 = function (message, options) {
		var digestbytes = util.lWordsToBytes(RIPEMD160._rmd160(message));
		return options && options.asBytes ? digestbytes :
			options && options.asString ? Binary.bytesToString(digestbytes) :
			util.bytesToHex(digestbytes);
	};

	// The core
	RIPEMD160._rmd160 = function (message)
	{
		// Convert to byte array
		if (message.constructor == String) message = UTF8.stringToBytes(message);

		var x = util.bytesToLWords(message),
		    len = message.length * 8;

		/* append padding */
		x[len >> 5] |= 0x80 << (len % 32);
		x[(((len + 64) >>> 9) << 4) + 14] = len;

		var h0 = 0x67452301;
		var h1 = 0xefcdab89;
		var h2 = 0x98badcfe;
		var h3 = 0x10325476;
		var h4 = 0xc3d2e1f0;

		for (var i = 0; i < x.length; i += 16) {
			var T;
			var A1 = h0, B1 = h1, C1 = h2, D1 = h3, E1 = h4;
			var A2 = h0, B2 = h1, C2 = h2, D2 = h3, E2 = h4;
			for (var j = 0; j <= 79; ++j) {
				T = safe_add(A1, rmd160_f(j, B1, C1, D1));
				T = safe_add(T, x[i + rmd160_r1[j]]);
				T = safe_add(T, rmd160_K1(j));
				T = safe_add(bit_rol(T, rmd160_s1[j]), E1);
				A1 = E1; E1 = D1; D1 = bit_rol(C1, 10); C1 = B1; B1 = T;
				T = safe_add(A2, rmd160_f(79-j, B2, C2, D2));
				T = safe_add(T, x[i + rmd160_r2[j]]);
				T = safe_add(T, rmd160_K2(j));
				T = safe_add(bit_rol(T, rmd160_s2[j]), E2);
				A2 = E2; E2 = D2; D2 = bit_rol(C2, 10); C2 = B2; B2 = T;
			}
			T = safe_add(h1, safe_add(C1, D2));
			h1 = safe_add(h2, safe_add(D1, E2));
			h2 = safe_add(h3, safe_add(E1, A2));
			h3 = safe_add(h4, safe_add(A1, B2));
			h4 = safe_add(h0, safe_add(B1, C2));
			h0 = T;
		}
		return [h0, h1, h2, h3, h4];
	}

	function rmd160_f(j, x, y, z)
	{
		return ( 0 <= j && j <= 15) ? (x ^ y ^ z) :
			(16 <= j && j <= 31) ? (x & y) | (~x & z) :
			(32 <= j && j <= 47) ? (x | ~y) ^ z :
			(48 <= j && j <= 63) ? (x & z) | (y & ~z) :
			(64 <= j && j <= 79) ? x ^ (y | ~z) :
			"rmd160_f: j out of range";
	}
	function rmd160_K1(j)
	{
		return ( 0 <= j && j <= 15) ? 0x00000000 :
			(16 <= j && j <= 31) ? 0x5a827999 :
			(32 <= j && j <= 47) ? 0x6ed9eba1 :
			(48 <= j && j <= 63) ? 0x8f1bbcdc :
			(64 <= j && j <= 79) ? 0xa953fd4e :
			"rmd160_K1: j out of range";
	}
	function rmd160_K2(j)
	{
		return ( 0 <= j && j <= 15) ? 0x50a28be6 :
			(16 <= j && j <= 31) ? 0x5c4dd124 :
			(32 <= j && j <= 47) ? 0x6d703ef3 :
			(48 <= j && j <= 63) ? 0x7a6d76e9 :
			(64 <= j && j <= 79) ? 0x00000000 :
			"rmd160_K2: j out of range";
	}
	var rmd160_r1 = [
		0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
		3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
		1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
		4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
	];
	var rmd160_r2 = [
		5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
		6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
		15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
		8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
		12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
	];
	var rmd160_s1 = [
		11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
		7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
		11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
		11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
		9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
	];
	var rmd160_s2 = [
		8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
		9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
		9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
		15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
		8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
	];

	/*
	 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
	 * to work around bugs in some JS interpreters.
	 */
	function safe_add(x, y)
	{
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	}

	/*
	 * Bitwise rotate a 32-bit number to the left.
	 */
	function bit_rol(num, cnt)
	{
		return (num << cnt) | (num >>> (32 - cnt));
	}
})();
;
/**
 * EventEmitter Mixin
 *
 * Designed to be used in conjunction with a mixin "augment" function,
 * such as http://chamnapchhorn.blogspot.com/2009/05/javascript-mixins.html
 *
 * @usage augment(MyClass, EventEmitter);
 * my_inst = new MyClass();
 * my_inst.on('someEvent', function(e){ console.dir(e); });
 * my_inst.trigger('someEvent', {eventProp:'value'});
 * 
 * @example
 * // create a 'class'
 * MyClass = function() {}
 * // augment it with EventEmitter
 * EventEmitter.augment(MyClass.prototype);
 * // create a method, which triggers an event
 * MyClass.prototype.scrollComplete = function() {
 *     this.trigger('scrolled', {baz:'eck'});
 * };
 * 
 * // this callback is pulled out into a named function so that we can unbind it
 * var callback = function(e) {
 *     console.log('the scrolled event was fired! this.foo='+this.foo+', e.baz='+e.baz);
 * };
 * // create an instance of th class
 * var myinstance = new MyClass();
 * // set a property on the instance
 * myinstance.foo = 'bar';
 * // bind to the scrollComplete event
 * myinstance.on('scrolled', callback, myinstance);
 * // fire the method, which should trigger the event and therefore our callback
 * myinstance.scrollComplete();
 * // unbind the event, so that our callback should not get called
 * myinstance.removeListener('scrolled', callback);
 * // this should now not fire the callback
 * myinstance.scrollComplete();
 */
var EventEmitter = function() {};
/**
 * Bind a callback to an event, with an option scope context
 *
 * @param {string} name the name of the event
 * @param {function} callback the callback function to fire when the event is triggered
 * @param {object} context the scope to use for the callback (which will become 'this' inside the callback)
 */
EventEmitter.prototype.on = function(name, callback, context) {
    if (!context) context = this;
    if (!this._listeners) this._listeners = {};
    if (!this._listeners[name]) this._listeners[name] = [];
    if (!this._unbinders) this._unbinders = {};
    if (!this._unbinders[name]) this._unbinders[name] = [];
    var f = function(e) {
        callback.apply(context, [e]);
    };
    this._unbinders[name].push(callback);
    this._listeners[name].push(f);
};
/**
 * Trigger an event, firing all bound callbacks
 * 
 * @param {string} name the name of the event
 * @param {object} event the event object to be passed through to the callback
 */
EventEmitter.prototype.trigger = function(name, event) {
    if (event === undefined) event = {}
    if (!this._listeners) this._listeners = {};
    if (!this._listeners[name]) return;
    var i = this._listeners[name].length;
    while (i--) this._listeners[name][i](event);
};
/**
 * Remove a bound listener
 * 
 * @param {string} name the name of the event
 * @param {object} event the event object to be passed through to the callback
 */
EventEmitter.prototype.removeListener = function(name, callback) {
    if (!this._unbinders) this._unbinders = {};
    if (!this._unbinders[name]) return;
    var i = this._unbinders[name].length;
    while (i--) {
        if (this._unbinders[name][i] === callback) {
            this._unbinders[name].splice(i, 1);
            this._listeners[name].splice(i, 1);
        }
    }
};
/**
 * Augment an object with the EventEmitter mixin
 * 
 * @param {object} obj The object to be augmented (often an object's protoype)
 */
EventEmitter.augment = function(obj) {
    for (var method in EventEmitter.prototype) {
        if (!obj[method]) obj[method] = EventEmitter.prototype[method];
    }
};
;
;
;
;
;
;
;
;
;
;
;
;return { Bitcoin: window.Bitcoin, Crypto: window.Crypto } })(null, {})
module.exports = (function(module,window){
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
;
// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)
;
// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
  this.i = 0;
  this.j = 0;
  this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
  var i, j, t;
  for(i = 0; i < 256; ++i)
    this.S[i] = i;
  j = 0;
  for(i = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  this.i = 0;
  this.j = 0;
}

function ARC4next() {
  var t;
  this.i = (this.i + 1) & 255;
  this.j = (this.j + this.S[this.i]) & 255;
  t = this.S[this.i];
  this.S[this.i] = this.S[this.j];
  this.S[this.j] = t;
  return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
  return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;
;
// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

var rng_state;
var rng_pool;
var rng_pptr;

// Mix in a 32-bit integer into the pool
function rng_seed_int(x) {
  rng_pool[rng_pptr++] ^= x & 255;
  rng_pool[rng_pptr++] ^= (x >> 8) & 255;
  rng_pool[rng_pptr++] ^= (x >> 16) & 255;
  rng_pool[rng_pptr++] ^= (x >> 24) & 255;
  if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

// Mix in the current time (w/milliseconds) into the pool
function rng_seed_time() {
  rng_seed_int(new Date().getTime());
}

// Initialize the pool with junk if needed.
if(rng_pool == null) {
  rng_pool = new Array();
  rng_pptr = 0;
  var t;
  if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
    // Extract entropy (256 bits) from NS4 RNG if available
    var z = window.crypto.random(32);
    for(t = 0; t < z.length; ++t)
      rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
  }  
  while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
    t = Math.floor(65536 * Math.random());
    rng_pool[rng_pptr++] = t >>> 8;
    rng_pool[rng_pptr++] = t & 255;
  }
  rng_pptr = 0;
  rng_seed_time();
  //rng_seed_int(window.screenX);
  //rng_seed_int(window.screenY);
}

function rng_get_byte() {
  if(rng_state == null) {
    rng_seed_time();
    rng_state = prng_newstate();
    rng_state.init(rng_pool);
    for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
      rng_pool[rng_pptr] = 0;
    rng_pptr = 0;
    //rng_pool = null;
  }
  // TODO: allow reseeding after first request
  return rng_state.next();
}

function rng_get_bytes(ba) {
  var i;
  for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;
;
// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// Only Fp curves implemented for now

// Requires jsbn.js and jsbn2.js

// ----------------
// ECFieldElementFp

// constructor
function ECFieldElementFp(q,x) {
    this.x = x;
    // TODO if(x.compareTo(q) >= 0) error
    this.q = q;
}

function feFpEquals(other) {
    if(other == this) return true;
    return (this.q.equals(other.q) && this.x.equals(other.x));
}

function feFpToBigInteger() {
    return this.x;
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}

function feFpAdd(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}

function feFpSubtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}

function feFpMultiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}

function feFpDivide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}

ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;

// ----------------
// ECPointFp

// constructor
function ECPointFp(curve,x,y,z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    // Projective coordinates: either zinv == null or z * zinv == 1
    // z and zinv are just BigIntegers, not fieldElements
    if(z == null) {
      this.z = BigInteger.ONE;
    }
    else {
      this.z = z;
    }
    this.zinv = null;
    //TODO: compression flag
}

function pointFpGetX() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpGetY() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpEquals(other) {
    if(other == this) return true;
    if(this.isInfinity()) return other.isInfinity();
    if(other.isInfinity()) return this.isInfinity();
    var u, v;
    // u = Y2 * Z1 - Y1 * Z2
    u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
    if(!u.equals(BigInteger.ZERO)) return false;
    // v = X2 * Z1 - X1 * Z2
    v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
    return v.equals(BigInteger.ZERO);
}

function pointFpIsInfinity() {
    if((this.x == null) && (this.y == null)) return true;
    return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}

function pointFpNegate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}

function pointFpAdd(b) {
    if(this.isInfinity()) return b;
    if(b.isInfinity()) return this;

    // u = Y2 * Z1 - Y1 * Z2
    var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
    // v = X2 * Z1 - X1 * Z2
    var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

    if(BigInteger.ZERO.equals(v)) {
        if(BigInteger.ZERO.equals(u)) {
            return this.twice(); // this == b, so double
        }
	return this.curve.getInfinity(); // this = -b, so infinity
    }

    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();
    var x2 = b.x.toBigInteger();
    var y2 = b.y.toBigInteger();

    var v2 = v.square();
    var v3 = v2.multiply(v);
    var x1v2 = x1.multiply(v2);
    var zu2 = u.square().multiply(this.z);

    // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
    var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
    // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
    var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
    // z3 = v^3 * z1 * z2
    var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpTwice() {
    if(this.isInfinity()) return this;
    if(this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

    // TODO: optimized handling of constants
    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();

    var y1z1 = y1.multiply(this.z);
    var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
    var a = this.curve.a.toBigInteger();

    // w = 3 * x1^2 + a * z1^2
    var w = x1.square().multiply(THREE);
    if(!BigInteger.ZERO.equals(a)) {
      w = w.add(this.z.square().multiply(a));
    }
    w = w.mod(this.curve.q);
    // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
    var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
    // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
    var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
    // z3 = 8 * (y1 * z1)^3
    var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

// Simple NAF (Non-Adjacent Form) multiplication algorithm
// TODO: modularize the multiplication algorithm
function pointFpMultiply(k) {
    if(this.isInfinity()) return this;
    if(k.signum() == 0) return this.curve.getInfinity();

    var e = k;
    var h = e.multiply(new BigInteger("3"));

    var neg = this.negate();
    var R = this;

    var i;
    for(i = h.bitLength() - 2; i > 0; --i) {
	R = R.twice();

	var hBit = h.testBit(i);
	var eBit = e.testBit(i);

	if (hBit != eBit) {
	    R = R.add(hBit ? this : neg);
	}
    }

    return R;
}

// Compute this*j + x*k (simultaneous multiplication)
function pointFpMultiplyTwo(j,x,k) {
  var i;
  if(j.bitLength() > k.bitLength())
    i = j.bitLength() - 1;
  else
    i = k.bitLength() - 1;

  var R = this.curve.getInfinity();
  var both = this.add(x);
  while(i >= 0) {
    R = R.twice();
    if(j.testBit(i)) {
      if(k.testBit(i)) {
        R = R.add(both);
      }
      else {
        R = R.add(this);
      }
    }
    else {
      if(k.testBit(i)) {
        R = R.add(x);
      }
    }
    --i;
  }

  return R;
}

ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;

// ----------------
// ECCurveFp

// constructor
function ECCurveFp(q,a,b) {
    this.q = q;
    this.a = this.fromBigInteger(a);
    this.b = this.fromBigInteger(b);
    this.infinity = new ECPointFp(this, null, null);
}

function curveFpGetQ() {
    return this.q;
}

function curveFpGetA() {
    return this.a;
}

function curveFpGetB() {
    return this.b;
}

function curveFpEquals(other) {
    if(other == this) return true;
    return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
}

function curveFpGetInfinity() {
    return this.infinity;
}

function curveFpFromBigInteger(x) {
    return new ECFieldElementFp(this.q, x);
}

// for now, work with hex strings because they're easier in JS
function curveFpDecodePointHex(s) {
    switch(parseInt(s.substr(0,2), 16)) { // first byte
    case 0:
	return this.infinity;
    case 2:
    case 3:
	// point compression not supported yet
	return null;
    case 4:
    case 6:
    case 7:
	var len = (s.length - 2) / 2;
	var xHex = s.substr(2, len);
	var yHex = s.substr(len+2, len);

	return new ECPointFp(this,
			     this.fromBigInteger(new BigInteger(xHex, 16)),
			     this.fromBigInteger(new BigInteger(yHex, 16)));

    default: // unsupported
	return null;
    }
}

ECCurveFp.prototype.getQ = curveFpGetQ;
ECCurveFp.prototype.getA = curveFpGetA;
ECCurveFp.prototype.getB = curveFpGetB;
ECCurveFp.prototype.equals = curveFpEquals;
ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;
;
// Named EC curves

// Requires ec.js, jsbn.js, and jsbn2.js

// ----------------
// X9ECParameters

// constructor
function X9ECParameters(curve,g,n,h) {
    this.curve = curve;
    this.g = g;
    this.n = n;
    this.h = h;
}

function x9getCurve() {
    return this.curve;
}

function x9getG() {
    return this.g;
}

function x9getN() {
    return this.n;
}

function x9getH() {
    return this.h;
}

X9ECParameters.prototype.getCurve = x9getCurve;
X9ECParameters.prototype.getG = x9getG;
X9ECParameters.prototype.getN = x9getN;
X9ECParameters.prototype.getH = x9getH;

// ----------------
// SECNamedCurves

function fromHex(s) { return new BigInteger(s, 16); }

function secp128r1() {
    // p = 2^128 - 2^97 - 1
    var p = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");
    var b = fromHex("E87579C11079F43DD824993C2CEE5ED3");
    //byte[] S = Hex.decode("000E0D4D696E6768756151750CC03A4473D03679");
    var n = fromHex("FFFFFFFE0000000075A30D1B9038A115");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "161FF7528B899B2D0C28607CA52C5B86"
		+ "CF5AC8395BAFEB13C02DA292DDED7A83");
    return new X9ECParameters(curve, G, n, h);
}

function secp160k1() {
    // p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
    var a = BigInteger.ZERO;
    var b = fromHex("7");
    //byte[] S = null;
    var n = fromHex("0100000000000000000001B8FA16DFAB9ACA16B6B3");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"
                + "938CF935318FDCED6BC28286531733C3F03C4FEE");
    return new X9ECParameters(curve, G, n, h);
}

function secp160r1() {
    // p = 2^160 - 2^31 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");
    var b = fromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
    //byte[] S = Hex.decode("1053CDE42C14D696E67687561517533BF3F83345");
    var n = fromHex("0100000000000000000001F4C8F927AED3CA752257");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
		+ "4A96B5688EF573284664698968C38BB913CBFC82"
		+ "23A628553168947D59DCC912042351377AC5FB32");
    return new X9ECParameters(curve, G, n, h);
}

function secp192k1() {
    // p = 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
    var a = BigInteger.ZERO;
    var b = fromHex("3");
    //byte[] S = null;
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
                + "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D");
    return new X9ECParameters(curve, G, n, h);
}

function secp192r1() {
    // p = 2^192 - 2^64 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
    var b = fromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
    //byte[] S = Hex.decode("3045AE6FC8422F64ED579528D38120EAE12196D5");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
                + "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
    return new X9ECParameters(curve, G, n, h);
}

function secp224r1() {
    // p = 2^224 - 2^96 + 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    var b = fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    //byte[] S = Hex.decode("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
    return new X9ECParameters(curve, G, n, h);
}

function secp256k1() {
    // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    var a = BigInteger.ZERO;
    var b = fromHex("7");
    //byte[] S = null;
    var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	            + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    return new X9ECParameters(curve, G, n, h);
}

function secp256r1() {
    // p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
    var p = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    var a = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    var b = fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    //byte[] S = Hex.decode("C49D360886E704936A6678E1139D26B7819F7E90");
    var n = fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
		+ "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    return new X9ECParameters(curve, G, n, h);
}

// TODO: make this into a proper hashtable
function getSECCurveByName(name) {
    if(name == "secp128r1") return secp128r1();
    if(name == "secp160k1") return secp160k1();
    if(name == "secp160r1") return secp160r1();
    if(name == "secp192k1") return secp192k1();
    if(name == "secp192r1") return secp192r1();
    if(name == "secp224r1") return secp224r1();
    if(name == "secp256k1") return secp256k1();
    if(name == "secp256r1") return secp256r1();
    return null;
}
;
/*!
 * Crypto-JS v2.0.0
 * http://code.google.com/p/crypto-js/
 * Copyright (c) 2009, Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
(function(){

var base64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Global Crypto object
var Crypto = window.Crypto = {};

// Crypto utilities
var util = Crypto.util = {

	// Bit-wise rotate left
	rotl: function (n, b) {
		return (n << b) | (n >>> (32 - b));
	},

	// Bit-wise rotate right
	rotr: function (n, b) {
		return (n << (32 - b)) | (n >>> b);
	},

	// Swap big-endian to little-endian and vice versa
	endian: function (n) {

		// If number given, swap endian
		if (n.constructor == Number) {
			return util.rotl(n,  8) & 0x00FF00FF |
			       util.rotl(n, 24) & 0xFF00FF00;
		}

		// Else, assume array and swap all items
		for (var i = 0; i < n.length; i++)
			n[i] = util.endian(n[i]);
		return n;

	},

	// Generate an array of any length of random bytes
	randomBytes: function (n) {
		for (var bytes = []; n > 0; n--)
			bytes.push(Math.floor(Math.random() * 256));
		return bytes;
	},

	// Convert a byte array to big-endian 32-bit words
	bytesToWords: function (bytes) {
		for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
			words[b >>> 5] |= bytes[i] << (24 - b % 32);
		return words;
	},

	// Convert big-endian 32-bit words to a byte array
	wordsToBytes: function (words) {
		for (var bytes = [], b = 0; b < words.length * 32; b += 8)
			bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
		return bytes;
	},

	// Convert a byte array to a hex string
	bytesToHex: function (bytes) {
		for (var hex = [], i = 0; i < bytes.length; i++) {
			hex.push((bytes[i] >>> 4).toString(16));
			hex.push((bytes[i] & 0xF).toString(16));
		}
		return hex.join("");
	},

	// Convert a hex string to a byte array
	hexToBytes: function (hex) {
		for (var bytes = [], c = 0; c < hex.length; c += 2)
			bytes.push(parseInt(hex.substr(c, 2), 16));
		return bytes;
	},

	// Convert a byte array to a base-64 string
	bytesToBase64: function (bytes) {

		// Use browser-native function if it exists
		if (typeof btoa == "function") return btoa(Binary.bytesToString(bytes));

		for(var base64 = [], i = 0; i < bytes.length; i += 3) {
			var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
			for (var j = 0; j < 4; j++) {
				if (i * 8 + j * 6 <= bytes.length * 8)
					base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
				else base64.push("=");
			}
		}

		return base64.join("");

	},

	// Convert a base-64 string to a byte array
	base64ToBytes: function (base64) {

		// Use browser-native function if it exists
		if (typeof atob == "function") return Binary.stringToBytes(atob(base64));

		// Remove non-base-64 characters
		base64 = base64.replace(/[^A-Z0-9+\/]/ig, "");

		for (var bytes = [], i = 0, imod4 = 0; i < base64.length; imod4 = ++i % 4) {
			if (imod4 == 0) continue;
			bytes.push(((base64map.indexOf(base64.charAt(i - 1)) & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2)) |
			           (base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2)));
		}

		return bytes;

	}

};

// Crypto mode namespace
Crypto.mode = {};

// Crypto character encodings
var charenc = Crypto.charenc = {};

// UTF-8 encoding
var UTF8 = charenc.UTF8 = {

	// Convert a string to a byte array
	stringToBytes: function (str) {
		return Binary.stringToBytes(unescape(encodeURIComponent(str)));
	},

	// Convert a byte array to a string
	bytesToString: function (bytes) {
		return decodeURIComponent(escape(Binary.bytesToString(bytes)));
	}

};

// Binary encoding
var Binary = charenc.Binary = {

	// Convert a string to a byte array
	stringToBytes: function (str) {
		for (var bytes = [], i = 0; i < str.length; i++)
			bytes.push(str.charCodeAt(i));
		return bytes;
	},

	// Convert a byte array to a string
	bytesToString: function (bytes) {
		for (var str = [], i = 0; i < bytes.length; i++)
			str.push(String.fromCharCode(bytes[i]));
		return str.join("");
	}

};

})();
;
/*!
 * Crypto-JS v2.0.0
 * http://code.google.com/p/crypto-js/
 * Copyright (c) 2009, Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
(function(){

// Shortcuts
var C = Crypto,
    util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8,
    Binary = charenc.Binary;

// Constants
var K = [ 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
          0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
          0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
          0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
          0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
          0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
          0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
          0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
          0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
          0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
          0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
          0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
          0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
          0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
          0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
          0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2 ];

// Public API
var SHA256 = C.SHA256 = function (message, options) {
	var digestbytes = util.wordsToBytes(SHA256._sha256(message));
	return options && options.asBytes ? digestbytes :
	       options && options.asString ? Binary.bytesToString(digestbytes) :
	       util.bytesToHex(digestbytes);
};

// The core
SHA256._sha256 = function (message) {

	// Convert to byte array
	if (message.constructor == String) message = UTF8.stringToBytes(message);
	/* else, assume byte array already */

	var m = util.bytesToWords(message),
	    l = message.length * 8,
	    H = [ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	          0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 ],
	    w = [],
	    a, b, c, d, e, f, g, h, i, j,
	    t1, t2;

	// Padding
	m[l >> 5] |= 0x80 << (24 - l % 32);
	m[((l + 64 >> 9) << 4) + 15] = l;

	for (var i = 0; i < m.length; i += 16) {

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		for (var j = 0; j < 64; j++) {

			if (j < 16) w[j] = m[j + i];
			else {

				var gamma0x = w[j - 15],
				    gamma1x = w[j - 2],
				    gamma0  = ((gamma0x << 25) | (gamma0x >>>  7)) ^
				              ((gamma0x << 14) | (gamma0x >>> 18)) ^
				               (gamma0x >>> 3),
				    gamma1  = ((gamma1x <<  15) | (gamma1x >>> 17)) ^
				              ((gamma1x <<  13) | (gamma1x >>> 19)) ^
				               (gamma1x >>> 10);

				w[j] = gamma0 + (w[j - 7] >>> 0) +
				       gamma1 + (w[j - 16] >>> 0);

			}

			var ch  = e & f ^ ~e & g,
			    maj = a & b ^ a & c ^ b & c,
			    sigma0 = ((a << 30) | (a >>>  2)) ^
			             ((a << 19) | (a >>> 13)) ^
			             ((a << 10) | (a >>> 22)),
			    sigma1 = ((e << 26) | (e >>>  6)) ^
			             ((e << 21) | (e >>> 11)) ^
			             ((e <<  7) | (e >>> 25));


			t1 = (h >>> 0) + sigma1 + ch + (K[j]) + (w[j] >>> 0);
			t2 = sigma0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;

		}

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;

	}

	return H;

};

// Package private blocksize
SHA256._blocksize = 16;

})();
;
/*!
 * Crypto-JS v2.0.0
 * http://code.google.com/p/crypto-js/
 * Copyright (c) 2009, Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 *
 * A JavaScript implementation of the RIPEMD-160 Algorithm
 * Version 2.2 Copyright Jeremy Lin, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 * Also http://www.ocf.berkeley.edu/~jjlin/jsotp/
 * Ported to Crypto-JS by Stefan Thomas.
 */

(function () {
	// Shortcuts
	var C = Crypto,
    util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8,
    Binary = charenc.Binary;

	// Convert a byte array to little-endian 32-bit words
	util.bytesToLWords = function (bytes) {

		var output = Array(bytes.length >> 2);
		for (var i = 0; i < output.length; i++)
			output[i] = 0;
		for (var i = 0; i < bytes.length * 8; i += 8)
			output[i>>5] |= (bytes[i / 8] & 0xFF) << (i%32);
		return output;
	};

	// Convert little-endian 32-bit words to a byte array
	util.lWordsToBytes = function (words) {
		var output = [];
		for (var i = 0; i < words.length * 32; i += 8)
			output.push((words[i>>5] >>> (i % 32)) & 0xff);
		return output;
	};

	// Public API
	var RIPEMD160 = C.RIPEMD160 = function (message, options) {
		var digestbytes = util.lWordsToBytes(RIPEMD160._rmd160(message));
		return options && options.asBytes ? digestbytes :
			options && options.asString ? Binary.bytesToString(digestbytes) :
			util.bytesToHex(digestbytes);
	};

	// The core
	RIPEMD160._rmd160 = function (message)
	{
		// Convert to byte array
		if (message.constructor == String) message = UTF8.stringToBytes(message);

		var x = util.bytesToLWords(message),
		    len = message.length * 8;

		/* append padding */
		x[len >> 5] |= 0x80 << (len % 32);
		x[(((len + 64) >>> 9) << 4) + 14] = len;

		var h0 = 0x67452301;
		var h1 = 0xefcdab89;
		var h2 = 0x98badcfe;
		var h3 = 0x10325476;
		var h4 = 0xc3d2e1f0;

		for (var i = 0; i < x.length; i += 16) {
			var T;
			var A1 = h0, B1 = h1, C1 = h2, D1 = h3, E1 = h4;
			var A2 = h0, B2 = h1, C2 = h2, D2 = h3, E2 = h4;
			for (var j = 0; j <= 79; ++j) {
				T = safe_add(A1, rmd160_f(j, B1, C1, D1));
				T = safe_add(T, x[i + rmd160_r1[j]]);
				T = safe_add(T, rmd160_K1(j));
				T = safe_add(bit_rol(T, rmd160_s1[j]), E1);
				A1 = E1; E1 = D1; D1 = bit_rol(C1, 10); C1 = B1; B1 = T;
				T = safe_add(A2, rmd160_f(79-j, B2, C2, D2));
				T = safe_add(T, x[i + rmd160_r2[j]]);
				T = safe_add(T, rmd160_K2(j));
				T = safe_add(bit_rol(T, rmd160_s2[j]), E2);
				A2 = E2; E2 = D2; D2 = bit_rol(C2, 10); C2 = B2; B2 = T;
			}
			T = safe_add(h1, safe_add(C1, D2));
			h1 = safe_add(h2, safe_add(D1, E2));
			h2 = safe_add(h3, safe_add(E1, A2));
			h3 = safe_add(h4, safe_add(A1, B2));
			h4 = safe_add(h0, safe_add(B1, C2));
			h0 = T;
		}
		return [h0, h1, h2, h3, h4];
	}

	function rmd160_f(j, x, y, z)
	{
		return ( 0 <= j && j <= 15) ? (x ^ y ^ z) :
			(16 <= j && j <= 31) ? (x & y) | (~x & z) :
			(32 <= j && j <= 47) ? (x | ~y) ^ z :
			(48 <= j && j <= 63) ? (x & z) | (y & ~z) :
			(64 <= j && j <= 79) ? x ^ (y | ~z) :
			"rmd160_f: j out of range";
	}
	function rmd160_K1(j)
	{
		return ( 0 <= j && j <= 15) ? 0x00000000 :
			(16 <= j && j <= 31) ? 0x5a827999 :
			(32 <= j && j <= 47) ? 0x6ed9eba1 :
			(48 <= j && j <= 63) ? 0x8f1bbcdc :
			(64 <= j && j <= 79) ? 0xa953fd4e :
			"rmd160_K1: j out of range";
	}
	function rmd160_K2(j)
	{
		return ( 0 <= j && j <= 15) ? 0x50a28be6 :
			(16 <= j && j <= 31) ? 0x5c4dd124 :
			(32 <= j && j <= 47) ? 0x6d703ef3 :
			(48 <= j && j <= 63) ? 0x7a6d76e9 :
			(64 <= j && j <= 79) ? 0x00000000 :
			"rmd160_K2: j out of range";
	}
	var rmd160_r1 = [
		0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
		3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
		1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
		4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
	];
	var rmd160_r2 = [
		5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
		6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
		15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
		8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
		12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
	];
	var rmd160_s1 = [
		11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
		7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
		11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
		11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
		9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
	];
	var rmd160_s2 = [
		8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
		9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
		9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
		15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
		8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
	];

	/*
	 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
	 * to work around bugs in some JS interpreters.
	 */
	function safe_add(x, y)
	{
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	}

	/*
	 * Bitwise rotate a 32-bit number to the left.
	 */
	function bit_rol(num, cnt)
	{
		return (num << cnt) | (num >>> (32 - cnt));
	}
})();
;
/**
 * EventEmitter Mixin
 *
 * Designed to be used in conjunction with a mixin "augment" function,
 * such as http://chamnapchhorn.blogspot.com/2009/05/javascript-mixins.html
 *
 * @usage augment(MyClass, EventEmitter);
 * my_inst = new MyClass();
 * my_inst.on('someEvent', function(e){ console.dir(e); });
 * my_inst.trigger('someEvent', {eventProp:'value'});
 * 
 * @example
 * // create a 'class'
 * MyClass = function() {}
 * // augment it with EventEmitter
 * EventEmitter.augment(MyClass.prototype);
 * // create a method, which triggers an event
 * MyClass.prototype.scrollComplete = function() {
 *     this.trigger('scrolled', {baz:'eck'});
 * };
 * 
 * // this callback is pulled out into a named function so that we can unbind it
 * var callback = function(e) {
 *     console.log('the scrolled event was fired! this.foo='+this.foo+', e.baz='+e.baz);
 * };
 * // create an instance of th class
 * var myinstance = new MyClass();
 * // set a property on the instance
 * myinstance.foo = 'bar';
 * // bind to the scrollComplete event
 * myinstance.on('scrolled', callback, myinstance);
 * // fire the method, which should trigger the event and therefore our callback
 * myinstance.scrollComplete();
 * // unbind the event, so that our callback should not get called
 * myinstance.removeListener('scrolled', callback);
 * // this should now not fire the callback
 * myinstance.scrollComplete();
 */
var EventEmitter = function() {};
/**
 * Bind a callback to an event, with an option scope context
 *
 * @param {string} name the name of the event
 * @param {function} callback the callback function to fire when the event is triggered
 * @param {object} context the scope to use for the callback (which will become 'this' inside the callback)
 */
EventEmitter.prototype.on = function(name, callback, context) {
    if (!context) context = this;
    if (!this._listeners) this._listeners = {};
    if (!this._listeners[name]) this._listeners[name] = [];
    if (!this._unbinders) this._unbinders = {};
    if (!this._unbinders[name]) this._unbinders[name] = [];
    var f = function(e) {
        callback.apply(context, [e]);
    };
    this._unbinders[name].push(callback);
    this._listeners[name].push(f);
};
/**
 * Trigger an event, firing all bound callbacks
 * 
 * @param {string} name the name of the event
 * @param {object} event the event object to be passed through to the callback
 */
EventEmitter.prototype.trigger = function(name, event) {
    if (event === undefined) event = {}
    if (!this._listeners) this._listeners = {};
    if (!this._listeners[name]) return;
    var i = this._listeners[name].length;
    while (i--) this._listeners[name][i](event);
};
/**
 * Remove a bound listener
 * 
 * @param {string} name the name of the event
 * @param {object} event the event object to be passed through to the callback
 */
EventEmitter.prototype.removeListener = function(name, callback) {
    if (!this._unbinders) this._unbinders = {};
    if (!this._unbinders[name]) return;
    var i = this._unbinders[name].length;
    while (i--) {
        if (this._unbinders[name][i] === callback) {
            this._unbinders[name].splice(i, 1);
            this._listeners[name].splice(i, 1);
        }
    }
};
/**
 * Augment an object with the EventEmitter mixin
 * 
 * @param {object} obj The object to be augmented (often an object's protoype)
 */
EventEmitter.augment = function(obj) {
    for (var method in EventEmitter.prototype) {
        if (!obj[method]) obj[method] = EventEmitter.prototype[method];
    }
};
;
(function (exports) {
  var Bitcoin = exports;

  if ('object' !== typeof module) {
    Bitcoin.EventEmitter = EventEmitter;
  }
})(
  'object' === typeof module ? module.exports : (window.Bitcoin = {})
);

/*
  function makeKeypair()
  {
    // Generate private key
    var n = ecparams.getN();
    var n1 = n.subtract(BigInteger.ONE);
    var r = new BigInteger(n.bitLength(), rng);
    
    var privateKey = r.mod(n1).add(BigInteger.ONE);
    
    // Generate public key
    var G = ecparams.getG();
    var publicPoint = G.multiply(privateKey);

    return {priv: privateKey, pubkey: publicPoint};
  };

  function serializeTransaction(tx)
  {
    var buffer = [];
    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(tx.version)]));
    buffer = buffer.concat(numToVarInt(tx.ins.length));
    for (var i = 0; i < tx.ins.length; i++) {
      var txin = tx.ins[i];
      buffer = buffer.concat(Crypto.util.base64ToBytes(txin.outpoint.hash));
      buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(txin.index)]));
      var scriptBytes = Crypto.util.base64ToBytes(txin.script);
      buffer = buffer.concat(numToVarInt(scriptBytes.length));
      buffer = buffer.concat(scriptBytes);
      buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(txin.sequence)]));
    }
    buffer = buffer.concat(numToVarInt(tx.outs.length));
    for (var i = 0; i < tx.outs.length; i++) {
      var txout = tx.outs[i];
      var valueHex = (new BigInteger(txout.value, 10)).toString(16);
      while (valueHex.length < 16) valueHex = "0" + valueHex;
      buffer = buffer.concat(Crypto.util.hexToBytes(valueHex));
      var scriptBytes = Crypto.util.base64ToBytes(txout.script);
      buffer = buffer.concat(numToVarInt(scriptBytes.length));
      buffer = buffer.concat(scriptBytes);
    }
    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(tx.lock_time)]));
    
    return buffer;
  };

  var OP_CODESEPARATOR = 171;

  var SIGHASH_ALL = 1;
  var SIGHASH_NONE = 2;
  var SIGHASH_SINGLE = 3;
  var SIGHASH_ANYONECANPAY = 80;

  function hashTransactionForSignature(scriptCode, tx, inIndex, hashType)
  {
    // TODO: We need to actually deep copy here
    var txTmp = tx;

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    scriptCode = scriptCode.filter(function (val) {
      return val !== OP_CODESEPARATOR;
    });
    
    // Blank out other inputs' signatures
    for (var i = 0; i < txTmp.ins.length; i++) {
      txTmp.ins[i].script = Crypto.util.bytesToBase64([]);
    }
    txTmp.ins[inIndex].script = Crypto.util.bytesToBase64(scriptCode);

    // Blank out some of the outputs
    if ((hashType & 0x1f) == SIGHASH_NONE) {
      txTmp.outs = [];

      // Let the others update at will
      for (var i = 0; i < txTmp.ins.length; i++)
        if (i != inIndex)
          txTmp.ins[i].sequence = 0;
    } else if ((hashType & 0x1f) == SIGHASH_SINGLE) {
      // TODO: Implement
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (hashType & SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
    }
    
    var buffer = serializeTransaction(txTmp);
    
    buffer.concat(Crypto.util.wordsToBytes([parseInt(hashType)]));

    console.log(buffer);
    
    return Crypto.SHA256(Crypto.SHA256(buffer, {asBytes: true}), {asBytes: true});
  };

  function verifyTransactionSignature(tx) {
    var hash = hashTransactionForSignature([], tx, 0, 0);
    return Crypto.util.bytesToHex(hash);
  };

  function numToVarInt(i)
  {
    // TODO: THIS IS TOTALLY UNTESTED!
    if (i < 0xfd) {
      // unsigned char
      return [i];
    } else if (i <= 1<<16) {
      // unsigned short (LE)
      return [0xfd, i >>> 8, i & 255];
    } else if (i <= 1<<32) {
      // unsigned int (LE)
      return [0xfe].concat(Crypto.util.wordsToBytes([i]));
    } else {
      // unsigned long long (LE)
      return [0xff].concat(Crypto.util.wordsToBytes([i >>> 32, i]));
    }
  };

  var testTx = {
    "version":"1",
    "lock_time":"0",
    "block": {
      "hash":"N/A",
      "height":115806
    },
    "index":6,
    "hash":"WUFzjKubG1kqfJWMb4qZdlhU2F3l5NGXN7AUg8Jwl14=",
    "ins":[{
      "outpoint":{
        "hash":"nqcbMM1oRhfLdZga11q7x0CpUMujm+vtxHXO9V0gnwE=",
        "index":0
      },
      "script":"RzBEAiB2XXkx1pca9SlfCmCGNUVf+h2sAFBttcxG1VnypIcvEgIgXrOp7LSdYBYp3nPsQAz8BOLD3K4pAlXfZImP1rkzk2EBQQRi7NcODzNfnVqLtG79Axp5UF6EhFIhCmzqKqssfKpfCIOmzCuXEeDFUFvFzeGLJx5N+wp2qRS1TqYezGD3yERk",
      "sequence":4294967295
    }],
    "outs":[{
      "value":"3000000000",
      "script":"dqkUBLZwqhAPRVgZvwI8MN5gLHbU8NOIrA=="
    },{
      "value":"25937000000",
      "script":"dqkUQ82gJ0O5vOBg6yK5/yorLLV5zLKIrA=="
    }]
  };

   TODO: Make this stuff into test cases ;)
   $(function () {
   var key = new Bitcoin.ECKey(Crypto.util.hexToBytes("5c0b98e524ad188ddef35dc6abba13c34a351a05409e5d285403718b93336a4a"));
   key = new Bitcoin.ECKey(Crypto.util.hexToBytes("180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19"));
   //console.log(key.getBitcoinAddress().toString());
   //var message = Crypto.util.hexToBytes("2aec28d323ee7b06a799d540d224b351161fe48967174ca5e43164e86137da11");
   //message = [0];
   //var out = key.sign(message);
   //console.log("pubkey: "+Crypto.util.bytesToHex(key.getPub()));
   //console.log("sig: "+Crypto.util.bytesToHex(out));

   //console.log(key.verify(message, out));

   //console.log(Bitcoin.ECDSA.verify(message, Crypto.util.hexToBytes("3046022100dffbc26774fc841bbe1c1362fd643609c6e42dcb274763476d87af2c0597e89e022100c59e3c13b96b316cae9fa0ab0260612c7a133a6fe2b3445b6bf80b3123bf274d"), Crypto.util.hexToBytes("0401de173aa944eacf7e44e5073baca93fb34fe4b7897a1c82c92dfdc8a1f75ef58cd1b06e8052096980cb6e1ad6d3df143c34b3d7394bae2782a4df570554c2fb")));

   //console.log(Bitcoin.ECDSA.verify(Crypto.util.hexToBytes("230aba77ccde46bb17fcb0295a92c0cc42a6ea9f439aaadeb0094625f49e6ed8"), Crypto.util.hexToBytes("3046022100a3ee5408f0003d8ef00ff2e0537f54ba09771626ff70dca1f01296b05c510e85022100d4dc70a5bb50685b65833a97e536909a6951dd247a2fdbde6688c33ba6d6407501"),Crypto.util.hexToBytes("04a19c1f07c7a0868d86dbb37510305843cc730eb3bea8a99d92131f44950cecd923788419bfef2f635fad621d753f30d4b4b63b29da44b4f3d92db974537ad5a4")));
   //console.log(Bitcoin.ECDSA.verify(Crypto.util.hexToBytes("c2c75bb77d7a5acddceb1d45ceef58e7451fd0d3abc9d4c16df7848eefafe00d"), Crypto.util.hexToBytes("3045022100ff9362dadcbf1f6ef954bc8eb27144bbb4f49abd32be1eb04c311151dcf4bcf802205112c2ca6a25aefb8be98bf460c5a9056c01253f31e118d80b81ec9604e3201a01"),Crypto.util.hexToBytes("04fe62ce7892ec209310c176ef7f06565865e286e8699e884603657efa9aa51086785099d544d4e04f1f7b4b065205c1783fade8daf4ba1e0d1962292e8eb722cd")));
   });
   //
*/
;
// BigInteger monkey patching
BigInteger.valueOf = nbv;

/**
 * Returns a byte array representation of the big integer.
 *
 * This returns the absolute of the contained value in big endian
 * form. A value of zero results in an empty array.
 */
BigInteger.prototype.toByteArrayUnsigned = function () {
  var ba = this.abs().toByteArray();
  if (ba.length) {
    if (ba[0] == 0) {
      ba = ba.slice(1);
    }
    return ba.map(function (v) {
      return (v < 0) ? v + 256 : v;
    });
  } else {
    // Empty array, nothing to do
    return ba;
  }
};

/**
 * Turns a byte array into a big integer.
 *
 * This function will interpret a byte array as a big integer in big
 * endian notation and ignore leading zeros.
 */
BigInteger.fromByteArrayUnsigned = function (ba) {
  if (!ba.length) {
    return ba.valueOf(0);
  } else if (ba[0] & 0x80) {
    // Prepend a zero so the BigInteger class doesn't mistake this
    // for a negative integer.
    return new BigInteger([0].concat(ba));
  } else {
    return new BigInteger(ba);
  }
};

/**
 * Converts big integer to signed byte representation.
 *
 * The format for this value uses a the most significant bit as a sign
 * bit. If the most significant bit is already occupied by the
 * absolute value, an extra byte is prepended and the sign bit is set
 * there.
 *
 * Examples:
 *
 *      0 =>     0x00
 *      1 =>     0x01
 *     -1 =>     0x81
 *    127 =>     0x7f
 *   -127 =>     0xff
 *    128 =>   0x0080
 *   -128 =>   0x8080
 *    255 =>   0x00ff
 *   -255 =>   0x80ff
 *  16300 =>   0x3fac
 * -16300 =>   0xbfac
 *  62300 => 0x00f35c
 * -62300 => 0x80f35c
 */
BigInteger.prototype.toByteArraySigned = function () {
  var val = this.abs().toByteArrayUnsigned();
  var neg = this.compareTo(BigInteger.ZERO) < 0;

  if (neg) {
    if (val[0] & 0x80) {
      val.unshift(0x80);
    } else {
      val[0] |= 0x80;
    }
  } else {
    if (val[0] & 0x80) {
      val.unshift(0x00);
    }
  }

  return val;
};

/**
 * Parse a signed big integer byte representation.
 *
 * For details on the format please see BigInteger.toByteArraySigned.
 */
BigInteger.fromByteArraySigned = function (ba) {
  // Check for negative value
  if (ba[0] & 0x80) {
    // Remove sign bit
    ba[0] &= 0x7f;

    return BigInteger.fromByteArrayUnsigned(ba).negate();
  } else {
    return BigInteger.fromByteArrayUnsigned(ba);
  }
};

// Console ignore
var names = ["log", "debug", "info", "warn", "error", "assert", "dir",
             "dirxml", "group", "groupEnd", "time", "timeEnd", "count",
             "trace", "profile", "profileEnd"];

if ("undefined" == typeof window.console) window.console = {};
for (var i = 0; i < names.length; ++i)
  if ("undefined" == typeof window.console[names[i]])
    window.console[names[i]] = function() {};

// Bitcoin utility functions
Bitcoin.Util = {
  /**
   * Cross-browser compatibility version of Array.isArray.
   */
  isArray: Array.isArray || function(o)
  {
    return Object.prototype.toString.call(o) === '[object Array]';
  },

  /**
   * Create an array of a certain length filled with a specific value.
   */
  makeFilledArray: function (len, val)
  {
    var array = [];
    var i = 0;
    while (i < len) {
      array[i++] = val;
    }
    return array;
  },

  /**
   * Turn an integer into a "var_int".
   *
   * "var_int" is a variable length integer used by Bitcoin's binary format.
   *
   * Returns a byte array.
   */
  numToVarInt: function (i)
  {
    if (i < 0xfd) {
      // unsigned char
      return [i];
    } else if (i <= 1<<16) {
      // unsigned short (LE)
      return [0xfd, i >>> 8, i & 255];
    } else if (i <= 1<<32) {
      // unsigned int (LE)
      return [0xfe].concat(Crypto.util.wordsToBytes([i]));
    } else {
      // unsigned long long (LE)
      return [0xff].concat(Crypto.util.wordsToBytes([i >>> 32, i]));
    }
  },

  /**
   * Parse a Bitcoin value byte array, returning a BigInteger.
   */
  valueToBigInt: function (valueBuffer)
  {
    if (valueBuffer instanceof BigInteger) return valueBuffer;

    // Prepend zero byte to prevent interpretation as negative integer
    return BigInteger.fromByteArrayUnsigned(valueBuffer);
  },

  /**
   * Format a Bitcoin value as a string.
   *
   * Takes a BigInteger or byte-array and returns that amount of Bitcoins in a
   * nice standard formatting.
   *
   * Examples:
   * 12.3555
   * 0.1234
   * 900.99998888
   * 34.00
   */
  formatValue: function (valueBuffer) {
    var value = this.valueToBigInt(valueBuffer).toString();
    var integerPart = value.length > 8 ? value.substr(0, value.length-8) : '0';
    var decimalPart = value.length > 8 ? value.substr(value.length-8) : value;
    while (decimalPart.length < 8) decimalPart = "0"+decimalPart;
    decimalPart = decimalPart.replace(/0*$/, '');
    while (decimalPart.length < 2) decimalPart += "0";
    return integerPart+"."+decimalPart;
  },

  /**
   * Parse a floating point string as a Bitcoin value.
   *
   * Keep in mind that parsing user input is messy. You should always display
   * the parsed value back to the user to make sure we understood his input
   * correctly.
   */
  parseValue: function (valueString) {
    // TODO: Detect other number formats (e.g. comma as decimal separator)
    var valueComp = valueString.split('.');
    var integralPart = valueComp[0];
    var fractionalPart = valueComp[1] || "0";
    while (fractionalPart.length < 8) fractionalPart += "0";
    fractionalPart = fractionalPart.replace(/^0+/g, '');
    var value = BigInteger.valueOf(parseInt(integralPart));
    value = value.multiply(BigInteger.valueOf(100000000));
    value = value.add(BigInteger.valueOf(parseInt(fractionalPart)));
    return value;
  },

  /**
   * Calculate RIPEMD160(SHA256(data)).
   *
   * Takes an arbitrary byte array as inputs and returns the hash as a byte
   * array.
   */
  sha256ripe160: function (data) {
    return Crypto.RIPEMD160(Crypto.SHA256(data, {asBytes: true}), {asBytes: true});
  }
};

for (var i in Crypto.util) {
  if (Crypto.util.hasOwnProperty(i)) {
    Bitcoin.Util[i] = Crypto.util[i];
  }
}
;
(function (Bitcoin) {
  Bitcoin.Base58 = {
    alphabet: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    validRegex: /^[1-9A-HJ-NP-Za-km-z]+$/,
    base: BigInteger.valueOf(58),

    /**
     * Convert a byte array to a base58-encoded string.
     *
     * Written by Mike Hearn for BitcoinJ.
     *   Copyright (c) 2011 Google Inc.
     *
     * Ported to JavaScript by Stefan Thomas.
     */
    encode: function (input) {
      var bi = BigInteger.fromByteArrayUnsigned(input);
      var chars = [];

      while (bi.compareTo(B58.base) >= 0) {
        var mod = bi.mod(B58.base);
        chars.unshift(B58.alphabet[mod.intValue()]);
        bi = bi.subtract(mod).divide(B58.base);
      }
      chars.unshift(B58.alphabet[bi.intValue()]);

      // Convert leading zeros too.
      for (var i = 0; i < input.length; i++) {
        if (input[i] == 0x00) {
          chars.unshift(B58.alphabet[0]);
        } else break;
      }

      return chars.join('');
    },

    /**
     * Convert a base58-encoded string to a byte array.
     *
     * Written by Mike Hearn for BitcoinJ.
     *   Copyright (c) 2011 Google Inc.
     *
     * Ported to JavaScript by Stefan Thomas.
     */
    decode: function (input) {
      var bi = BigInteger.valueOf(0);
      var leadingZerosNum = 0;
      for (var i = input.length - 1; i >= 0; i--) {
        var alphaIndex = B58.alphabet.indexOf(input[i]);
        if (alphaIndex < 0) {
          throw "Invalid character";
        }	
        bi = bi.add(BigInteger.valueOf(alphaIndex)
                    .multiply(B58.base.pow(input.length - 1 -i)));

        // This counts leading zero bytes
        if (input[i] == "1") leadingZerosNum++;
        else leadingZerosNum = 0;
      }
      var bytes = bi.toByteArrayUnsigned();

      // Add leading zeros
      while (leadingZerosNum-- > 0) bytes.unshift(0);

      return bytes;
    }
  };

  var B58 = Bitcoin.Base58;
})(
  'undefined' != typeof Bitcoin ? Bitcoin : module.exports
);
;
Bitcoin.Address = function (bytes) {
  if ("string" == typeof bytes) {
    bytes = Bitcoin.Address.decodeString(bytes);
  }
  this.hash = bytes;

  this.version = 0x00;
};

/**
 * Serialize this object as a standard Bitcoin address.
 *
 * Returns the address as a base58-encoded string in the standardized format.
 */
Bitcoin.Address.prototype.toString = function () {
  // Get a copy of the hash
  var hash = this.hash.slice(0);

  // Version
  hash.unshift(this.version);

  var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});

  var bytes = hash.concat(checksum.slice(0,4));

  return Bitcoin.Base58.encode(bytes);
};

Bitcoin.Address.prototype.getHashBase64 = function () {
  return Crypto.util.bytesToBase64(this.hash);
};

/**
 * Parse a Bitcoin address contained in a string.
 */
Bitcoin.Address.decodeString = function (string) {
  var bytes = Bitcoin.Base58.decode(string);

  var hash = bytes.slice(0, 21);

  var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});

  if (checksum[0] != bytes[21] ||
      checksum[1] != bytes[22] ||
      checksum[2] != bytes[23] ||
      checksum[3] != bytes[24]) {
    throw "Checksum validation failed!";
  }

  var version = hash.shift();

  if (version != 0) {
    throw "Version "+version+" not supported!";
  }

  return hash;
};
;
function integerToBytes(i, len) {
  var bytes = i.toByteArrayUnsigned();

  if (len < bytes.length) {
    bytes = bytes.slice(bytes.length-len);
  } else while (len > bytes.length) {
    bytes.unshift(0);
  }

  return bytes;
};

ECFieldElementFp.prototype.getByteLength = function () {
  return Math.floor((this.toBigInteger().bitLength() + 7) / 8);
};

ECPointFp.prototype.getEncoded = function (compressed) {
  var x = this.getX().toBigInteger();
  var y = this.getY().toBigInteger();

  // Get value as a 32-byte Buffer
  // Fixed length based on a patch by bitaddress.org and Casascius
  var enc = integerToBytes(x, 32);

  if (compressed) {
    if (y.isEven()) {
      // Compressed even pubkey
      // M = 02 || X
      enc.unshift(0x02);
    } else {
      // Compressed uneven pubkey
      // M = 03 || X
      enc.unshift(0x03);
    }
  } else {
    // Uncompressed pubkey
    // M = 04 || X || Y
    enc.unshift(0x04);
    enc = enc.concat(integerToBytes(y, 32));
  }
  return enc;
};

ECPointFp.decodeFrom = function (curve, enc) {
  var type = enc[0];
  var dataLen = enc.length-1;

  // Extract x and y as byte arrays
  var xBa = enc.slice(1, 1 + dataLen/2);
  var yBa = enc.slice(1 + dataLen/2, 1 + dataLen);

  // Prepend zero byte to prevent interpretation as negative integer
  xBa.unshift(0);
  yBa.unshift(0);

  // Convert to BigIntegers
  var x = new BigInteger(xBa);
  var y = new BigInteger(yBa);

  // Return point
  return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
};

ECPointFp.prototype.add2D = function (b) {
  if(this.isInfinity()) return b;
  if(b.isInfinity()) return this;

  if (this.x.equals(b.x)) {
    if (this.y.equals(b.y)) {
      // this = b, i.e. this must be doubled
      return this.twice();
    }
    // this = -b, i.e. the result is the point at infinity
    return this.curve.getInfinity();
  }

  var x_x = b.x.subtract(this.x);
  var y_y = b.y.subtract(this.y);
  var gamma = y_y.divide(x_x);

  var x3 = gamma.square().subtract(this.x).subtract(b.x);
  var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

  return new ECPointFp(this.curve, x3, y3);
};

ECPointFp.prototype.twice2D = function () {
  if (this.isInfinity()) return this;
  if (this.y.toBigInteger().signum() == 0) {
    // if y1 == 0, then (x1, y1) == (x1, -y1)
    // and hence this = -this and thus 2(x1, y1) == infinity
    return this.curve.getInfinity();
  }

  var TWO = this.curve.fromBigInteger(BigInteger.valueOf(2));
  var THREE = this.curve.fromBigInteger(BigInteger.valueOf(3));
  var gamma = this.x.square().multiply(THREE).add(this.curve.a).divide(this.y.multiply(TWO));

  var x3 = gamma.square().subtract(this.x.multiply(TWO));
  var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

  return new ECPointFp(this.curve, x3, y3);
};

ECPointFp.prototype.multiply2D = function (k) {
  if(this.isInfinity()) return this;
  if(k.signum() == 0) return this.curve.getInfinity();

  var e = k;
  var h = e.multiply(new BigInteger("3"));

  var neg = this.negate();
  var R = this;

  var i;
  for (i = h.bitLength() - 2; i > 0; --i) {
    R = R.twice();

    var hBit = h.testBit(i);
    var eBit = e.testBit(i);

    if (hBit != eBit) {
      R = R.add2D(hBit ? this : neg);
    }
  }

  return R;
};

ECPointFp.prototype.isOnCurve = function () {
  var x = this.getX().toBigInteger();
  var y = this.getY().toBigInteger();
  var a = this.curve.getA().toBigInteger();
  var b = this.curve.getB().toBigInteger();
  var n = this.curve.getQ();
  var lhs = y.multiply(y).mod(n);
  var rhs = x.multiply(x).multiply(x)
    .add(a.multiply(x)).add(b).mod(n);
  return lhs.equals(rhs);
};

ECPointFp.prototype.toString = function () {
  return '('+this.getX().toBigInteger().toString()+','+
    this.getY().toBigInteger().toString()+')';
};

/**
 * Validate an elliptic curve point.
 *
 * See SEC 1, section 3.2.2.1: Elliptic Curve Public Key Validation Primitive
 */
ECPointFp.prototype.validate = function () {
  var n = this.curve.getQ();

  // Check Q != O
  if (this.isInfinity()) {
    throw new Error("Point is at infinity.");
  }

  // Check coordinate bounds
  var x = this.getX().toBigInteger();
  var y = this.getY().toBigInteger();
  if (x.compareTo(BigInteger.ONE) < 0 ||
      x.compareTo(n.subtract(BigInteger.ONE)) > 0) {
    throw new Error('x coordinate out of bounds');
  }
  if (y.compareTo(BigInteger.ONE) < 0 ||
      y.compareTo(n.subtract(BigInteger.ONE)) > 0) {
    throw new Error('y coordinate out of bounds');
  }

  // Check y^2 = x^3 + ax + b (mod n)
  if (!this.isOnCurve()) {
    throw new Error("Point is not on the curve.");
  }

  // Check nQ = 0 (Q is a scalar multiple of G)
  if (this.multiply(n).isInfinity()) {
    // TODO: This check doesn't work - fix.
    throw new Error("Point is not a scalar multiple of G.");
  }

  return true;
};

function dmp(v) {
  if (!(v instanceof BigInteger)) v = v.toBigInteger();
  return Crypto.util.bytesToHex(v.toByteArrayUnsigned());
};

Bitcoin.ECDSA = (function () {
  var ecparams = getSECCurveByName("secp256k1");
  var rng = new SecureRandom();

  var P_OVER_FOUR = null;

  function implShamirsTrick(P, k, Q, l)
  {
    var m = Math.max(k.bitLength(), l.bitLength());
    var Z = P.add2D(Q);
    var R = P.curve.getInfinity();

    for (var i = m - 1; i >= 0; --i) {
      R = R.twice2D();

      R.z = BigInteger.ONE;

      if (k.testBit(i)) {
        if (l.testBit(i)) {
          R = R.add2D(Z);
        } else {
          R = R.add2D(P);
        }
      } else {
        if (l.testBit(i)) {
          R = R.add2D(Q);
        }
      }
    }

    return R;
  };

  var ECDSA = {
    getBigRandom: function (limit) {
      return new BigInteger(limit.bitLength(), rng)
        .mod(limit.subtract(BigInteger.ONE))
        .add(BigInteger.ONE)
      ;
    },
    sign: function (hash, priv) {
      var d = priv;
      var n = ecparams.getN();
      var e = BigInteger.fromByteArrayUnsigned(hash);

      do {
        var k = ECDSA.getBigRandom(n);
        var G = ecparams.getG();
        var Q = G.multiply(k);
        var r = Q.getX().toBigInteger().mod(n);
      } while (r.compareTo(BigInteger.ZERO) <= 0);

      var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

      return ECDSA.serializeSig(r, s);
    },

    verify: function (hash, sig, pubkey) {
      var r,s;
      if (Bitcoin.Util.isArray(sig)) {
        var obj = ECDSA.parseSig(sig);
        r = obj.r;
        s = obj.s;
      } else if ("object" === typeof sig && sig.r && sig.s) {
        r = sig.r;
        s = sig.s;
      } else {
        throw "Invalid value for signature";
      }

      var Q;
      if (pubkey instanceof ECPointFp) {
        Q = pubkey;
      } else if (Bitcoin.Util.isArray(pubkey)) {
        Q = ECPointFp.decodeFrom(ecparams.getCurve(), pubkey);
      } else {
        throw "Invalid format for pubkey value, must be byte array or ECPointFp";
      }
      var e = BigInteger.fromByteArrayUnsigned(hash);

      return ECDSA.verifyRaw(e, r, s, Q);
    },

    verifyRaw: function (e, r, s, Q) {
      var n = ecparams.getN();
      var G = ecparams.getG();

      if (r.compareTo(BigInteger.ONE) < 0 ||
          r.compareTo(n) >= 0)
        return false;

      if (s.compareTo(BigInteger.ONE) < 0 ||
          s.compareTo(n) >= 0)
        return false;

      var c = s.modInverse(n);

      var u1 = e.multiply(c).mod(n);
      var u2 = r.multiply(c).mod(n);

      // TODO(!!!): For some reason Shamir's trick isn't working with
      // signed message verification!? Probably an implementation
      // error!
      //var point = implShamirsTrick(G, u1, Q, u2);
      var point = G.multiply(u1).add(Q.multiply(u2));

      var v = point.getX().toBigInteger().mod(n);

      return v.equals(r);
    },

    /**
     * Serialize a signature into DER format.
     *
     * Takes two BigIntegers representing r and s and returns a byte array.
     */
    serializeSig: function (r, s) {
      var rBa = r.toByteArraySigned();
      var sBa = s.toByteArraySigned();

      var sequence = [];
      sequence.push(0x02); // INTEGER
      sequence.push(rBa.length);
      sequence = sequence.concat(rBa);

      sequence.push(0x02); // INTEGER
      sequence.push(sBa.length);
      sequence = sequence.concat(sBa);

      sequence.unshift(sequence.length);
      sequence.unshift(0x30); // SEQUENCE

      return sequence;
    },

    /**
     * Parses a byte array containing a DER-encoded signature.
     *
     * This function will return an object of the form:
     *
     * {
     *   r: BigInteger,
     *   s: BigInteger
     * }
     */
    parseSig: function (sig) {
      var cursor;
      if (sig[0] != 0x30)
        throw new Error("Signature not a valid DERSequence");

      cursor = 2;
      if (sig[cursor] != 0x02)
        throw new Error("First element in signature must be a DERInteger");;
      var rBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

      cursor += 2+sig[cursor+1];
      if (sig[cursor] != 0x02)
        throw new Error("Second element in signature must be a DERInteger");
      var sBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

      cursor += 2+sig[cursor+1];

      //if (cursor != sig.length)
      //  throw new Error("Extra bytes in signature");

      var r = BigInteger.fromByteArrayUnsigned(rBa);
      var s = BigInteger.fromByteArrayUnsigned(sBa);

      return {r: r, s: s};
    },

    parseSigCompact: function (sig) {
      if (sig.length !== 65) {
        throw "Signature has the wrong length";
      }

      // Signature is prefixed with a type byte storing three bits of
      // information.
      var i = sig[0] - 27;
      if (i < 0 || i > 7) {
        throw "Invalid signature type";
      }

      var n = ecparams.getN();
      var r = BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
      var s = BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);

      return {r: r, s: s, i: i};
    },

    /**
     * Recover a public key from a signature.
     *
     * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
     * Key Recovery Operation".
     *
     * http://www.secg.org/download/aid-780/sec1-v2.pdf
     */
    recoverPubKey: function (r, s, hash, i) {
      // The recovery parameter i has two bits.
      i = i & 3;

      // The less significant bit specifies whether the y coordinate
      // of the compressed point is even or not.
      var isYEven = i & 1;

      // The more significant bit specifies whether we should use the
      // first or second candidate key.
      var isSecondKey = i >> 1;

      var n = ecparams.getN();
      var G = ecparams.getG();
      var curve = ecparams.getCurve();
      var p = curve.getQ();
      var a = curve.getA().toBigInteger();
      var b = curve.getB().toBigInteger();

      // We precalculate (p + 1) / 4 where p is if the field order
      if (!P_OVER_FOUR) {
        P_OVER_FOUR = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
      }

      // 1.1 Compute x
      var x = isSecondKey ? r.add(n) : r;

      // 1.3 Convert x to point
      var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
      var beta = alpha.modPow(P_OVER_FOUR, p);

      var xorOdd = beta.isEven() ? (i % 2) : ((i+1) % 2);
      // If beta is even, but y isn't or vice versa, then convert it,
      // otherwise we're done and y == beta.
      var y = (beta.isEven() ? !isYEven : isYEven) ? beta : p.subtract(beta);

      // 1.4 Check that nR is at infinity
      var R = new ECPointFp(curve,
                            curve.fromBigInteger(x),
                            curve.fromBigInteger(y));
      R.validate();

      // 1.5 Compute e from M
      var e = BigInteger.fromByteArrayUnsigned(hash);
      var eNeg = BigInteger.ZERO.subtract(e).mod(n);

      // 1.6 Compute Q = r^-1 (sR - eG)
      var rInv = r.modInverse(n);
      var Q = implShamirsTrick(R, s, G, eNeg).multiply(rInv);

      Q.validate();
      if (!ECDSA.verifyRaw(e, r, s, Q)) {
        throw "Pubkey recovery unsuccessful";
      }

      var pubKey = new Bitcoin.ECKey();
      pubKey.pub = Q;
      return pubKey;
    },

    /**
     * Calculate pubkey extraction parameter.
     *
     * When extracting a pubkey from a signature, we have to
     * distinguish four different cases. Rather than putting this
     * burden on the verifier, Bitcoin includes a 2-bit value with the
     * signature.
     *
     * This function simply tries all four cases and returns the value
     * that resulted in a successful pubkey recovery.
     */
    calcPubkeyRecoveryParam: function (address, r, s, hash)
    {
      for (var i = 0; i < 4; i++) {
        try {
          var pubkey = Bitcoin.ECDSA.recoverPubKey(r, s, hash, i);
          if (pubkey.getBitcoinAddress().toString() == address) {
            return i;
          }
        } catch (e) {}
      }
      throw "Unable to find valid recovery factor";
    }
  };

  return ECDSA;
})();
;
Bitcoin.ECKey = (function () {
  var ECDSA = Bitcoin.ECDSA;
  var ecparams = getSECCurveByName("secp256k1");
  var rng = new SecureRandom();

  var ECKey = function (input) {
    if (!input) {
      // Generate new key
      var n = ecparams.getN();
      this.priv = ECDSA.getBigRandom(n);
    } else if (input instanceof BigInteger) {
      // Input is a private key value
      this.priv = input;
    } else if (Bitcoin.Util.isArray(input)) {
      // Prepend zero byte to prevent interpretation as negative integer
      this.priv = BigInteger.fromByteArrayUnsigned(input);
    } else if ("string" == typeof input) {
      if (input.length == 51 && input[0] == '5') {
        // Base58 encoded private key
        this.priv = BigInteger.fromByteArrayUnsigned(ECKey.decodeString(input));
      } else {
        // Prepend zero byte to prevent interpretation as negative integer
        this.priv = BigInteger.fromByteArrayUnsigned(Crypto.util.base64ToBytes(input));
      }
    }
    this.compressed = !!ECKey.compressByDefault;
  };

  /**
   * Whether public keys should be returned compressed by default.
   */
  ECKey.compressByDefault = false;

  /**
   * Set whether the public key should be returned compressed or not.
   */
  ECKey.prototype.setCompressed = function (v) {
    this.compressed = !!v;
  };

  /**
   * Return public key in DER encoding.
   */
  ECKey.prototype.getPub = function () {
    return this.getPubPoint().getEncoded(this.compressed);
  };

  /**
   * Return public point as ECPoint object.
   */
  ECKey.prototype.getPubPoint = function () {
    if (!this.pub) this.pub = ecparams.getG().multiply(this.priv);

    return this.pub;
  };

  /**
   * Get the pubKeyHash for this key.
   *
   * This is calculated as RIPE160(SHA256([encoded pubkey])) and returned as
   * a byte array.
   */
  ECKey.prototype.getPubKeyHash = function () {
    if (this.pubKeyHash) return this.pubKeyHash;

    return this.pubKeyHash = Bitcoin.Util.sha256ripe160(this.getPub());
  };

  ECKey.prototype.getBitcoinAddress = function () {
    var hash = this.getPubKeyHash();
    var addr = new Bitcoin.Address(hash);
    return addr;
  };

  ECKey.prototype.getExportedPrivateKey = function () {
    var hash = this.priv.toByteArrayUnsigned();
    while (hash.length < 32) hash.unshift(0);
    hash.unshift(0x80);
    var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
    var bytes = hash.concat(checksum.slice(0,4));
    return Bitcoin.Base58.encode(bytes);
  };

  ECKey.prototype.setPub = function (pub) {
    this.pub = ECPointFp.decodeFrom(ecparams.getCurve(), pub);
  };

  ECKey.prototype.toString = function (format) {
    if (format === "base64") {
      return Crypto.util.bytesToBase64(this.priv.toByteArrayUnsigned());
    } else {
      return Crypto.util.bytesToHex(this.priv.toByteArrayUnsigned());
    }
  };

  ECKey.prototype.sign = function (hash) {
    return ECDSA.sign(hash, this.priv);
  };

  ECKey.prototype.verify = function (hash, sig) {
    return ECDSA.verify(hash, sig, this.getPub());
  };

  /**
   * Parse an exported private key contained in a string.
   */
  ECKey.decodeString = function (string) {
    var bytes = Bitcoin.Base58.decode(string);

    var hash = bytes.slice(0, 33);

    var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});

    if (checksum[0] != bytes[33] ||
        checksum[1] != bytes[34] ||
        checksum[2] != bytes[35] ||
        checksum[3] != bytes[36]) {
      throw "Checksum validation failed!";
    }

    var version = hash.shift();

    if (version != 0x80) {
      throw "Version "+version+" not supported!";
    }

    return hash;
  };

  return ECKey;
})();
;
(function () {
  var Opcode = Bitcoin.Opcode = function (num) {
    this.code = num;
  };

  Opcode.prototype.toString = function () {
    return Opcode.reverseMap[this.code];
  };

  Opcode.map = {
    // push value
    OP_0         : 0,
    OP_FALSE     : 0,
    OP_PUSHDATA1 : 76,
    OP_PUSHDATA2 : 77,
    OP_PUSHDATA4 : 78,
    OP_1NEGATE   : 79,
    OP_RESERVED  : 80,
    OP_1         : 81,
    OP_TRUE      : 81,
    OP_2         : 82,
    OP_3         : 83,
    OP_4         : 84,
    OP_5         : 85,
    OP_6         : 86,
    OP_7         : 87,
    OP_8         : 88,
    OP_9         : 89,
    OP_10        : 90,
    OP_11        : 91,
    OP_12        : 92,
    OP_13        : 93,
    OP_14        : 94,
    OP_15        : 95,
    OP_16        : 96,

    // control
    OP_NOP       : 97,
    OP_VER       : 98,
    OP_IF        : 99,
    OP_NOTIF     : 100,
    OP_VERIF     : 101,
    OP_VERNOTIF  : 102,
    OP_ELSE      : 103,
    OP_ENDIF     : 104,
    OP_VERIFY    : 105,
    OP_RETURN    : 106,

    // stack ops
    OP_TOALTSTACK   : 107,
    OP_FROMALTSTACK : 108,
    OP_2DROP        : 109,
    OP_2DUP         : 110,
    OP_3DUP         : 111,
    OP_2OVER        : 112,
    OP_2ROT         : 113,
    OP_2SWAP        : 114,
    OP_IFDUP        : 115,
    OP_DEPTH        : 116,
    OP_DROP         : 117,
    OP_DUP          : 118,
    OP_NIP          : 119,
    OP_OVER         : 120,
    OP_PICK         : 121,
    OP_ROLL         : 122,
    OP_ROT          : 123,
    OP_SWAP         : 124,
    OP_TUCK         : 125,

    // splice ops
    OP_CAT          : 126,
    OP_SUBSTR       : 127,
    OP_LEFT         : 128,
    OP_RIGHT        : 129,
    OP_SIZE         : 130,

    // bit logic
    OP_INVERT       : 131,
    OP_AND          : 132,
    OP_OR           : 133,
    OP_XOR          : 134,
    OP_EQUAL        : 135,
    OP_EQUALVERIFY  : 136,
    OP_RESERVED1    : 137,
    OP_RESERVED2    : 138,

    // numeric
    OP_1ADD         : 139,
    OP_1SUB         : 140,
    OP_2MUL         : 141,
    OP_2DIV         : 142,
    OP_NEGATE       : 143,
    OP_ABS          : 144,
    OP_NOT          : 145,
    OP_0NOTEQUAL    : 146,

    OP_ADD          : 147,
    OP_SUB          : 148,
    OP_MUL          : 149,
    OP_DIV          : 150,
    OP_MOD          : 151,
    OP_LSHIFT       : 152,
    OP_RSHIFT       : 153,

    OP_BOOLAND             : 154,
    OP_BOOLOR              : 155,
    OP_NUMEQUAL            : 156,
    OP_NUMEQUALVERIFY      : 157,
    OP_NUMNOTEQUAL         : 158,
    OP_LESSTHAN            : 159,
    OP_GREATERTHAN         : 160,
    OP_LESSTHANOREQUAL     : 161,
    OP_GREATERTHANOREQUAL  : 162,
    OP_MIN                 : 163,
    OP_MAX                 : 164,

    OP_WITHIN              : 165,

    // crypto
    OP_RIPEMD160           : 166,
    OP_SHA1                : 167,
    OP_SHA256              : 168,
    OP_HASH160             : 169,
    OP_HASH256             : 170,
    OP_CODESEPARATOR       : 171,
    OP_CHECKSIG            : 172,
    OP_CHECKSIGVERIFY      : 173,
    OP_CHECKMULTISIG       : 174,
    OP_CHECKMULTISIGVERIFY : 175,

    // expansion
    OP_NOP1  : 176,
    OP_NOP2  : 177,
    OP_NOP3  : 178,
    OP_NOP4  : 179,
    OP_NOP5  : 180,
    OP_NOP6  : 181,
    OP_NOP7  : 182,
    OP_NOP8  : 183,
    OP_NOP9  : 184,
    OP_NOP10 : 185,

    // template matching params
    OP_PUBKEYHASH    : 253,
    OP_PUBKEY        : 254,
    OP_INVALIDOPCODE : 255
  };

  Opcode.reverseMap = [];

  for (var i in Opcode.map) {
    Opcode.reverseMap[Opcode.map[i]] = i;
  }
})();
;
(function () {
  var Opcode = Bitcoin.Opcode;

  // Make opcodes available as pseudo-constants
  for (var i in Opcode.map) {
    eval("var " + i + " = " + Opcode.map[i] + ";");
  }

  var Script = Bitcoin.Script = function (data) {
    if (!data) {
      this.buffer = [];
    } else if ("string" == typeof data) {
      this.buffer = Crypto.util.base64ToBytes(data);
    } else if (Bitcoin.Util.isArray(data)) {
      this.buffer = data;
    } else if (data instanceof Script) {
      this.buffer = data.buffer;
    } else {
      throw new Error("Invalid script");
    }

    this.parse();
  };

  /**
   * Update the parsed script representation.
   *
   * Each Script object stores the script in two formats. First as a raw byte
   * array and second as an array of "chunks", such as opcodes and pieces of
   * data.
   *
   * This method updates the chunks cache. Normally this is called by the
   * constructor and you don't need to worry about it. However, if you change
   * the script buffer manually, you should update the chunks using this method.
   */
  Script.prototype.parse = function () {
    var self = this;

    this.chunks = [];

    // Cursor
    var i = 0;

    // Read n bytes and store result as a chunk
    function readChunk(n) {
      self.chunks.push(self.buffer.slice(i, i + n));
      i += n;
    };

    while (i < this.buffer.length) {
      var opcode = this.buffer[i++];
      if (opcode >= 0xF0) {
        // Two byte opcode
        opcode = (opcode << 8) | this.buffer[i++];
      }

      var len;
      if (opcode > 0 && opcode < OP_PUSHDATA1) {
        // Read some bytes of data, opcode value is the length of data
        readChunk(opcode);
      } else if (opcode == OP_PUSHDATA1) {
        len = this.buffer[i++];
        readChunk(len);
      } else if (opcode == OP_PUSHDATA2) {
        len = (this.buffer[i++] << 8) | this.buffer[i++];
        readChunk(len);
      } else if (opcode == OP_PUSHDATA4) {
        len = (this.buffer[i++] << 24) |
          (this.buffer[i++] << 16) |
          (this.buffer[i++] << 8) |
          this.buffer[i++];
        readChunk(len);
      } else {
        this.chunks.push(opcode);
      }
    }
  };

  /**
   * Compare the script to known templates of scriptPubKey.
   *
   * This method will compare the script to a small number of standard script
   * templates and return a string naming the detected type.
   *
   * Currently supported are:
   * Address:
   *   Paying to a Bitcoin address which is the hash of a pubkey.
   *   OP_DUP OP_HASH160 [pubKeyHash] OP_EQUALVERIFY OP_CHECKSIG
   *
   * Pubkey:
   *   Paying to a public key directly.
   *   [pubKey] OP_CHECKSIG
   * 
   * Strange:
   *   Any other script (no template matched).
   */
  Script.prototype.getOutType = function () {

  if (this.chunks[this.chunks.length-1] == OP_CHECKMULTISIG && this.chunks[this.chunks.length-2] <= 3) {
    // Transfer to M-OF-N
    return 'Multisig';
  } else if (this.chunks.length == 5 &&
    this.chunks[0] == OP_DUP &&
    this.chunks[1] == OP_HASH160 &&
    this.chunks[3] == OP_EQUALVERIFY &&
    this.chunks[4] == OP_CHECKSIG) {
    // Transfer to Bitcoin address
    return 'Address';
  } else if (this.chunks.length == 2 &&
         this.chunks[1] == OP_CHECKSIG) {
    // Transfer to IP address
    return 'Pubkey';
  } else {
    return 'Strange';
  }   
}

  /**
   * Returns the affected address hash for this output.
   *
   * For standard transactions, this will return the hash of the pubKey that
   * can spend this output.
   *
   * In the future, for payToScriptHash outputs, this will return the
   * scriptHash. Note that non-standard and standard payToScriptHash transactions
   * look the same 
   *
   * This method is useful for indexing transactions.
   */
  Script.prototype.simpleOutHash = function ()
  {
    switch (this.getOutType()) {
    case 'Address':
      return this.chunks[2];
    case 'Pubkey':
      return Bitcoin.Util.sha256ripe160(this.chunks[0]);
    default:
      throw new Error("Encountered non-standard scriptPubKey");
    }
  };

  /**
   * Old name for Script#simpleOutHash.
   *
   * @deprecated
   */
  Script.prototype.simpleOutPubKeyHash = Script.prototype.simpleOutHash;

  /**
   * Compare the script to known templates of scriptSig.
   *
   * This method will compare the script to a small number of standard script
   * templates and return a string naming the detected type.
   *
   * WARNING: Use this method with caution. It merely represents a heuristic
   * based on common transaction formats. A non-standard transaction could
   * very easily match one of these templates by accident.
   *
   * Currently supported are:
   * Address:
   *   Paying to a Bitcoin address which is the hash of a pubkey.
   *   [sig] [pubKey]
   *
   * Pubkey:
   *   Paying to a public key directly.
   *   [sig]
   * 
   * Strange:
   *   Any other script (no template matched).
   */
  Script.prototype.getInType = function ()
  {
    if (this.chunks.length == 1 &&
        Bitcoin.Util.isArray(this.chunks[0])) {
      // Direct IP to IP transactions only have the signature in their scriptSig.
      // TODO: We could also check that the length of the data is correct.
      return 'Pubkey';
    } else if (this.chunks.length == 2 &&
               Bitcoin.Util.isArray(this.chunks[0]) &&
               Bitcoin.Util.isArray(this.chunks[1])) {
      return 'Address';
    } else {
      return 'Strange';
    }
  };

  /**
   * Returns the affected public key for this input.
   *
   * This currently only works with payToPubKeyHash transactions. It will also
   * work in the future for standard payToScriptHash transactions that use a
   * single public key.
   *
   * However for multi-key and other complex transactions, this will only return
   * one of the keys or raise an error. Therefore, it is recommended for indexing
   * purposes to use Script#simpleInHash or Script#simpleOutHash instead.
   *
   * @deprecated
   */
  Script.prototype.simpleInPubKey = function ()
  {
    switch (this.getInType()) {
    case 'Address':
      return this.chunks[1];
    case 'Pubkey':
      // TODO: Theoretically, we could recover the pubkey from the sig here.
      //       See https://bitcointalk.org/?topic=6430.0
      throw new Error("Script does not contain pubkey.");
    default:
      throw new Error("Encountered non-standard scriptSig");
    }
  };

  /**
   * Returns the affected address hash for this input.
   *
   * For standard transactions, this will return the hash of the pubKey that
   * can spend this output.
   *
   * In the future, for standard payToScriptHash inputs, this will return the
   * scriptHash.
   *
   * Note: This function provided for convenience. If you have the corresponding
   * scriptPubKey available, you are urged to use Script#simpleOutHash instead
   * as it is more reliable for non-standard payToScriptHash transactions.
   *
   * This method is useful for indexing transactions.
   */
  Script.prototype.simpleInHash = function ()
  {
    return Bitcoin.Util.sha256ripe160(this.simpleInPubKey());
  };

  /**
   * Old name for Script#simpleInHash.
   *
   * @deprecated
   */
  Script.prototype.simpleInPubKeyHash = Script.prototype.simpleInHash;

  /**
   * Add an op code to the script.
   */
  Script.prototype.writeOp = function (opcode)
  {
    this.buffer.push(opcode);
    this.chunks.push(opcode);
  };

  /**
   * Add a data chunk to the script.
   */
  Script.prototype.writeBytes = function (data)
  {
    if (data.length < OP_PUSHDATA1) {
      this.buffer.push(data.length);
    } else if (data.length <= 0xff) {
      this.buffer.push(OP_PUSHDATA1);
      this.buffer.push(data.length);
    } else if (data.length <= 0xffff) {
      this.buffer.push(OP_PUSHDATA2);
      this.buffer.push(data.length & 0xff);
      this.buffer.push((data.length >>> 8) & 0xff);
    } else {
      this.buffer.push(OP_PUSHDATA4);
      this.buffer.push(data.length & 0xff);
      this.buffer.push((data.length >>> 8) & 0xff);
      this.buffer.push((data.length >>> 16) & 0xff);
      this.buffer.push((data.length >>> 24) & 0xff);
    }
    this.buffer = this.buffer.concat(data);
    this.chunks.push(data);
  };

  /**
   * Create a standard payToPubKeyHash output.
   */
  Script.createOutputScript = function (address)
  {
    var script = new Script();
    script.writeOp(OP_DUP);
    script.writeOp(OP_HASH160);
    script.writeBytes(address.hash);
    script.writeOp(OP_EQUALVERIFY);
    script.writeOp(OP_CHECKSIG);
    return script;
  };
  
  
  /**
   * Extract bitcoin addresses from an output script
   */
  Script.prototype.extractAddresses = function (addresses)
  { 
    switch (this.getOutType()) {
    case 'Address':
      addresses.push(new Address(this.chunks[2]));
      return 1;
    case 'Pubkey':
      addresses.push(new Address(Util.sha256ripe160(this.chunks[0])));
      return 1;
    case 'Multisig':
      for (var i = 1; i < this.chunks.length-2; ++i) {
        addresses.push(new Address(Util.sha256ripe160(this.chunks[i])));
      }
      return this.chunks[0] - OP_1 + 1;
    default:
      throw new Error("Encountered non-standard scriptPubKey");
    }
  };

  /**
   * Create an m-of-n output script
   */
  Script.createMultiSigOutputScript = function (m, pubkeys)
  {
    var script = new Bitcoin.Script();
    
    script.writeOp(OP_1 + m - 1);
    
    for (var i = 0; i < pubkeys.length; ++i) {
      script.writeBytes(pubkeys[i]);
    }
    
    script.writeOp(OP_1 + pubkeys.length - 1);

    script.writeOp(OP_CHECKMULTISIG);

    return script;
  };

  /**
   * Create a standard payToPubKeyHash input.
   */
  Script.createInputScript = function (signature, pubKey)
  {
    var script = new Script();
    script.writeBytes(signature);
    script.writeBytes(pubKey);
    return script;
  };

  Script.prototype.clone = function ()
  {
    return new Script(this.buffer);
  };
})();
;
(function () {
  var Script = Bitcoin.Script;

  var Transaction = Bitcoin.Transaction = function (doc) {
    this.version = 1;
    this.lock_time = 0;
    this.ins = [];
    this.outs = [];
    this.timestamp = null;
    this.block = null;

    if (doc) {
      if (doc.hash) this.hash = doc.hash;
      if (doc.version) this.version = doc.version;
      if (doc.lock_time) this.lock_time = doc.lock_time;
      if (doc.ins && doc.ins.length) {
        for (var i = 0; i < doc.ins.length; i++) {
          this.addInput(new TransactionIn(doc.ins[i]));
        }
      }
      if (doc.outs && doc.outs.length) {
        for (var i = 0; i < doc.outs.length; i++) {
          this.addOutput(new TransactionOut(doc.outs[i]));
        }
      }
      if (doc.timestamp) this.timestamp = doc.timestamp;
      if (doc.block) this.block = doc.block;
    }
  };

  /**
   * Turn transaction data into Transaction objects.
   *
   * Takes an array of plain JavaScript objects containing transaction data and
   * returns an array of Transaction objects.
   */
  Transaction.objectify = function (txs) {
    var objs = [];
    for (var i = 0; i < txs.length; i++) {
      objs.push(new Transaction(txs[i]));
    }
    return objs;
  };

  /**
   * Create a new txin.
   *
   * Can be called with an existing TransactionIn object to add it to the
   * transaction. Or it can be called with a Transaction object and an integer
   * output index, in which case a new TransactionIn object pointing to the
   * referenced output will be created.
   *
   * Note that this method does not sign the created input.
   */
  Transaction.prototype.addInput = function (tx, outIndex) {
    if (arguments[0] instanceof TransactionIn) {
      this.ins.push(arguments[0]);
    } else {
      this.ins.push(new TransactionIn({
        outpoint: {
          hash: tx.hash,
          index: outIndex
        },
        script: new Bitcoin.Script(),
        sequence: 4294967295
      }));
    }
  };

  /**
   * Create a new txout.
   *
   * Can be called with an existing TransactionOut object to add it to the
   * transaction. Or it can be called with an Address object and a BigInteger
   * for the amount, in which case a new TransactionOut object with those
   * values will be created.
   */
  Transaction.prototype.addOutput = function (address, value) {
    if (arguments[0] instanceof TransactionOut) {
      this.outs.push(arguments[0]);
    } else {
      if (value instanceof BigInteger) {
        value = value.toByteArrayUnsigned().reverse();
        while (value.length < 8) value.push(0);
      } else if (Bitcoin.Util.isArray(value)) {
        // Nothing to do
      }

      this.outs.push(new TransactionOut({
        value: value,
        script: Script.createOutputScript(address)
      }));
    }
  };

  /**
   * Serialize this transaction.
   *
   * Returns the transaction as a byte array in the standard Bitcoin binary
   * format. This method is byte-perfect, i.e. the resulting byte array can
   * be hashed to get the transaction's standard Bitcoin hash.
   */
  Transaction.prototype.serialize = function ()
  {
    var buffer = [];
    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(this.version)]).reverse());
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(this.ins.length));
    for (var i = 0; i < this.ins.length; i++) {
      var txin = this.ins[i];
      buffer = buffer.concat(Crypto.util.base64ToBytes(txin.outpoint.hash));
      buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(txin.outpoint.index)]).reverse());
      var scriptBytes = txin.script.buffer;
      buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
      buffer = buffer.concat(scriptBytes);
      buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(txin.sequence)]).reverse());
    }
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(this.outs.length));
    for (var i = 0; i < this.outs.length; i++) {
      var txout = this.outs[i];
      buffer = buffer.concat(txout.value);
      var scriptBytes = txout.script.buffer;
      buffer = buffer.concat(Bitcoin.Util.numToVarInt(scriptBytes.length));
      buffer = buffer.concat(scriptBytes);
    }
    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(this.lock_time)]).reverse());

    return buffer;
  };

  var OP_CODESEPARATOR = 171;

  var SIGHASH_ALL = 1;
  var SIGHASH_NONE = 2;
  var SIGHASH_SINGLE = 3;
  var SIGHASH_ANYONECANPAY = 80;

  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input. This
   * method copies the transaction, makes the necessary changes based on the
   * hashType, serializes and finally hashes the result. This hash can then be
   * used to sign the transaction input in question.
   */
  Transaction.prototype.hashTransactionForSignature =
  function (connectedScript, inIndex, hashType)
  {
    var txTmp = this.clone();

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible
    // incompatibilities.
    /*scriptCode = scriptCode.filter(function (val) {
     return val !== OP_CODESEPARATOR;
     });*/

    // Blank out other inputs' signatures
    for (var i = 0; i < txTmp.ins.length; i++) {
      txTmp.ins[i].script = new Script();
    }

    txTmp.ins[inIndex].script = connectedScript;

    // Blank out some of the outputs
    if ((hashType & 0x1f) == SIGHASH_NONE) {
      txTmp.outs = [];

      // Let the others update at will
      for (var i = 0; i < txTmp.ins.length; i++)
        if (i != inIndex)
          txTmp.ins[i].sequence = 0;
    } else if ((hashType & 0x1f) == SIGHASH_SINGLE) {
      // TODO: Implement
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (hashType & SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
    }

    var buffer = txTmp.serialize();

    buffer = buffer.concat(Crypto.util.wordsToBytes([parseInt(hashType)]).reverse());

    var hash1 = Crypto.SHA256(buffer, {asBytes: true});

    return Crypto.SHA256(hash1, {asBytes: true});
  };

  /**
   * Calculate and return the transaction's hash.
   */
  Transaction.prototype.getHash = function ()
  {
    var buffer = this.serialize();
    return Crypto.SHA256(Crypto.SHA256(buffer, {asBytes: true}), {asBytes: true});
  };

  /**
   * Create a copy of this transaction object.
   */
  Transaction.prototype.clone = function ()
  {
    var newTx = new Transaction();
    newTx.version = this.version;
    newTx.lock_time = this.lock_time;
    for (var i = 0; i < this.ins.length; i++) {
      var txin = this.ins[i].clone();
      newTx.addInput(txin);
    }
    for (var i = 0; i < this.outs.length; i++) {
      var txout = this.outs[i].clone();
      newTx.addOutput(txout);
    }
    return newTx;
  };

  /**
   * Analyze how this transaction affects a wallet.
   *
   * Returns an object with properties 'impact', 'type' and 'addr'.
   *
   * 'impact' is an object, see Transaction#calcImpact.
   * 
   * 'type' can be one of the following:
   * 
   * recv:
   *   This is an incoming transaction, the wallet received money.
   *   'addr' contains the first address in the wallet that receives money
   *   from this transaction.
   *
   * self:
   *   This is an internal transaction, money was sent within the wallet.
   *   'addr' is undefined.
   *
   * sent:
   *   This is an outgoing transaction, money was sent out from the wallet.
   *   'addr' contains the first external address, i.e. the recipient.
   *
   * other:
   *   This method was unable to detect what the transaction does. Either it
   */
  Transaction.prototype.analyze = function (wallet) {
    if (!(wallet instanceof Bitcoin.Wallet)) return null;

    var allFromMe = true,
    allToMe = true,
    firstRecvHash = null,
    firstMeRecvHash = null,
    firstSendHash = null;

    for (var i = this.outs.length-1; i >= 0; i--) {
      var txout = this.outs[i];
      var hash = txout.script.simpleOutPubKeyHash();
      if (!wallet.hasHash(hash)) {
        allToMe = false;
      } else {
        firstMeRecvHash = hash;
      }
      firstRecvHash = hash;
    }
    for (var i = this.ins.length-1; i >= 0; i--) {
      var txin = this.ins[i];
      firstSendHash = txin.script.simpleInPubKeyHash();
      if (!wallet.hasHash(firstSendHash)) {
        allFromMe = false;
        break;
      }
    }

    var impact = this.calcImpact(wallet);

    var analysis = {};

    analysis.impact = impact;

    if (impact.sign > 0 && impact.value.compareTo(BigInteger.ZERO) > 0) {
      analysis.type = 'recv';
      analysis.addr = new Bitcoin.Address(firstMeRecvHash);
    } else if (allFromMe && allToMe) {
      analysis.type = 'self';
    } else if (allFromMe) {
      analysis.type = 'sent';
      // TODO: Right now, firstRecvHash is the first output, which - if the
      //       transaction was not generated by this library could be the
      //       change address.
      analysis.addr = new Bitcoin.Address(firstRecvHash);
    } else  {
      analysis.type = "other";
    }

    return analysis;
  };

  /**
   * Get a human-readable version of the data returned by Transaction#analyze.
   *
   * This is merely a convenience function. Clients should consider implementing
   * this themselves based on their UI, I18N, etc.
   */
  Transaction.prototype.getDescription = function (wallet) {
    var analysis = this.analyze(wallet);

    if (!analysis) return "";

    switch (analysis.type) {
    case 'recv':
      return "Received with "+analysis.addr;
      break;

    case 'sent':
      return "Payment to "+analysis.addr;
      break;

    case 'self':
      return "Payment to yourself";
      break;

    case 'other':
    default:
      return "";
    }
  };

  /**
   * Get the total amount of a transaction's outputs.
   */
  Transaction.prototype.getTotalOutValue = function () {
    var totalValue = BigInteger.ZERO;
    for (var j = 0; j < this.outs.length; j++) {
      var txout = this.outs[j];
      totalValue = totalValue.add(Bitcoin.Util.valueToBigInt(txout.value));
    }
    return totalValue;
  };

   /**
    * Old name for Transaction#getTotalOutValue.
    *
    * @deprecated
    */
   Transaction.prototype.getTotalValue = Transaction.prototype.getTotalOutValue;

  /**
   * Calculates the impact a transaction has on this wallet.
   *
   * Based on the its public keys, the wallet will calculate the
   * credit or debit of this transaction.
   *
   * It will return an object with two properties:
   *  - sign: 1 or -1 depending on sign of the calculated impact.
   *  - value: amount of calculated impact
   *
   * @returns Object Impact on wallet
   */
  Transaction.prototype.calcImpact = function (wallet) {
    if (!(wallet instanceof Bitcoin.Wallet)) return BigInteger.ZERO;

    // Calculate credit to us from all outputs
    var valueOut = BigInteger.ZERO;
    for (var j = 0; j < this.outs.length; j++) {
      var txout = this.outs[j];
      var hash = Crypto.util.bytesToBase64(txout.script.simpleOutPubKeyHash());
      if (wallet.hasHash(hash)) {
        valueOut = valueOut.add(Bitcoin.Util.valueToBigInt(txout.value));
      }
    }

    // Calculate debit to us from all ins
    var valueIn = BigInteger.ZERO;
    for (var j = 0; j < this.ins.length; j++) {
      var txin = this.ins[j];
      var hash = Crypto.util.bytesToBase64(txin.script.simpleInPubKeyHash());
      if (wallet.hasHash(hash)) {
        var fromTx = wallet.txIndex[txin.outpoint.hash];
        if (fromTx) {
          valueIn = valueIn.add(Bitcoin.Util.valueToBigInt(fromTx.outs[txin.outpoint.index].value));
        }
      }
    }
    if (valueOut.compareTo(valueIn) >= 0) {
      return {
        sign: 1,
        value: valueOut.subtract(valueIn)
      };
    } else {
      return {
        sign: -1,
        value: valueIn.subtract(valueOut)
      };
    }
  };

  var TransactionIn = Bitcoin.TransactionIn = function (data)
  {
    this.outpoint = data.outpoint;
    if (data.script instanceof Script) {
      this.script = data.script;
    } else {
      this.script = new Script(data.script);
    }
    this.sequence = data.sequence;
  };

  TransactionIn.prototype.clone = function ()
  {
    var newTxin = new TransactionIn({
      outpoint: {
        hash: this.outpoint.hash,
        index: this.outpoint.index
      },
      script: this.script.clone(),
      sequence: this.sequence
    });
    return newTxin;
  };

  var TransactionOut = Bitcoin.TransactionOut = function (data)
  {
    if (data.script instanceof Script) {
      this.script = data.script;
    } else {
      this.script = new Script(data.script);
    }

    if (Bitcoin.Util.isArray(data.value)) {
      this.value = data.value;
    } else if ("string" == typeof data.value) {
      var valueHex = (new BigInteger(data.value, 10)).toString(16);
      while (valueHex.length < 16) valueHex = "0" + valueHex;
      this.value = Crypto.util.hexToBytes(valueHex);
    }
  };

  TransactionOut.prototype.clone = function ()
  {
    var newTxout = new TransactionOut({
      script: this.script.clone(),
      value: this.value.slice(0)
    });
    return newTxout;
  };
})();


;
/**
 * Implements Bitcoin's feature for signing arbitrary messages.
 */
Bitcoin.Message = (function () {
  var Message = {};

  Message.magicPrefix = "Bitcoin Signed Message:\n";

  Message.makeMagicMessage = function (message) {
    var magicBytes = Crypto.charenc.UTF8.stringToBytes(Message.magicPrefix);
    var messageBytes = Crypto.charenc.UTF8.stringToBytes(message);

    var buffer = [];
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(magicBytes.length));
    buffer = buffer.concat(magicBytes);
    buffer = buffer.concat(Bitcoin.Util.numToVarInt(messageBytes.length));
    buffer = buffer.concat(messageBytes);

    return buffer;
  };

  Message.getHash = function (message) {
    var buffer = Message.makeMagicMessage(message);
    return Crypto.SHA256(Crypto.SHA256(buffer, {asBytes: true}), {asBytes: true});
  };

  Message.signMessage = function (key, message, compressed) {
    var hash = Message.getHash(message);

    var sig = key.sign(hash);

    var obj = Bitcoin.ECDSA.parseSig(sig);

    var address = key.getBitcoinAddress().toString();
    var i = Bitcoin.ECDSA.calcPubkeyRecoveryParam(address, obj.r, obj.s, hash);

    i += 27;
    if (compressed) i += 4;

    var rBa = obj.r.toByteArrayUnsigned();
    var sBa = obj.s.toByteArrayUnsigned();

    // Pad to 32 bytes per value
    while (rBa.length < 32) rBa.unshift(0);
    while (sBa.length < 32) sBa.unshift(0);

    sig = [i].concat(rBa).concat(sBa);

    return Crypto.util.bytesToBase64(sig);
  };

  Message.verifyMessage = function (address, sig, message) {
    sig = Crypto.util.base64ToBytes(sig);
    sig = Bitcoin.ECDSA.parseSigCompact(sig);

    var hash = Message.getHash(message);

    var isCompressed = !!(sig.i & 4);
    var pubKey = Bitcoin.ECDSA.recoverPubKey(sig.r, sig.s, hash, sig.i);

    pubKey.setCompressed(isCompressed);

    var expectedAddress = pubKey.getBitcoinAddress().toString();

    return (address === expectedAddress);
  };

  return Message;
})();
;
;return { Bitcoin: window.Bitcoin, Crypto: window.Crypto } })(null, {})
module.exports = (function(module,window){
var dbits;var canary=0xdeadbeefcafe;var j_lm=(canary&16777215)==15715070;function BigInteger(t,e,i){if(t!=null)if("number"==typeof t)this.fromNumber(t,e,i);else if(e==null&&"string"!=typeof t)this.fromString(t,256);else this.fromString(t,e)}function nbi(){return new BigInteger(null)}function am1(t,e,i,r,n,s){while(--s>=0){var o=e*this[t++]+i[r]+n;n=Math.floor(o/67108864);i[r++]=o&67108863}return n}function am2(t,e,i,r,n,s){var o=e&32767,u=e>>15;while(--s>=0){var a=this[t]&32767;var h=this[t++]>>15;var p=u*a+h*o;a=o*a+((p&32767)<<15)+i[r]+(n&1073741823);n=(a>>>30)+(p>>>15)+u*h+(n>>>30);i[r++]=a&1073741823}return n}function am3(t,e,i,r,n,s){var o=e&16383,u=e>>14;while(--s>=0){var a=this[t]&16383;var h=this[t++]>>14;var p=u*a+h*o;a=o*a+((p&16383)<<14)+i[r]+n;n=(a>>28)+(p>>14)+u*h;i[r++]=a&268435455}return n}if(j_lm&&navigator.appName=="Microsoft Internet Explorer"){BigInteger.prototype.am=am2;dbits=30}else if(j_lm&&navigator.appName!="Netscape"){BigInteger.prototype.am=am1;dbits=26}else{BigInteger.prototype.am=am3;dbits=28}BigInteger.prototype.DB=dbits;BigInteger.prototype.DM=(1<<dbits)-1;BigInteger.prototype.DV=1<<dbits;var BI_FP=52;BigInteger.prototype.FV=Math.pow(2,BI_FP);BigInteger.prototype.F1=BI_FP-dbits;BigInteger.prototype.F2=2*dbits-BI_FP;var BI_RM="0123456789abcdefghijklmnopqrstuvwxyz";var BI_RC=new Array;var rr,vv;rr="0".charCodeAt(0);for(vv=0;vv<=9;++vv)BI_RC[rr++]=vv;rr="a".charCodeAt(0);for(vv=10;vv<36;++vv)BI_RC[rr++]=vv;rr="A".charCodeAt(0);for(vv=10;vv<36;++vv)BI_RC[rr++]=vv;function int2char(t){return BI_RM.charAt(t)}function intAt(t,e){var i=BI_RC[t.charCodeAt(e)];return i==null?-1:i}function bnpCopyTo(t){for(var e=this.t-1;e>=0;--e)t[e]=this[e];t.t=this.t;t.s=this.s}function bnpFromInt(t){this.t=1;this.s=t<0?-1:0;if(t>0)this[0]=t;else if(t<-1)this[0]=t+DV;else this.t=0}function nbv(t){var e=nbi();e.fromInt(t);return e}function bnpFromString(t,e){var i;if(e==16)i=4;else if(e==8)i=3;else if(e==256)i=8;else if(e==2)i=1;else if(e==32)i=5;else if(e==4)i=2;else{this.fromRadix(t,e);return}this.t=0;this.s=0;var r=t.length,n=false,s=0;while(--r>=0){var o=i==8?t[r]&255:intAt(t,r);if(o<0){if(t.charAt(r)=="-")n=true;continue}n=false;if(s==0)this[this.t++]=o;else if(s+i>this.DB){this[this.t-1]|=(o&(1<<this.DB-s)-1)<<s;this[this.t++]=o>>this.DB-s}else this[this.t-1]|=o<<s;s+=i;if(s>=this.DB)s-=this.DB}if(i==8&&(t[0]&128)!=0){this.s=-1;if(s>0)this[this.t-1]|=(1<<this.DB-s)-1<<s}this.clamp();if(n)BigInteger.ZERO.subTo(this,this)}function bnpClamp(){var t=this.s&this.DM;while(this.t>0&&this[this.t-1]==t)--this.t}function bnToString(t){if(this.s<0)return"-"+this.negate().toString(t);var e;if(t==16)e=4;else if(t==8)e=3;else if(t==2)e=1;else if(t==32)e=5;else if(t==4)e=2;else return this.toRadix(t);var i=(1<<e)-1,r,n=false,s="",o=this.t;var u=this.DB-o*this.DB%e;if(o-->0){if(u<this.DB&&(r=this[o]>>u)>0){n=true;s=int2char(r)}while(o>=0){if(u<e){r=(this[o]&(1<<u)-1)<<e-u;r|=this[--o]>>(u+=this.DB-e)}else{r=this[o]>>(u-=e)&i;if(u<=0){u+=this.DB;--o}}if(r>0)n=true;if(n)s+=int2char(r)}}return n?s:"0"}function bnNegate(){var t=nbi();BigInteger.ZERO.subTo(this,t);return t}function bnAbs(){return this.s<0?this.negate():this}function bnCompareTo(t){var e=this.s-t.s;if(e!=0)return e;var i=this.t;e=i-t.t;if(e!=0)return this.s<0?-e:e;while(--i>=0)if((e=this[i]-t[i])!=0)return e;return 0}function nbits(t){var e=1,i;if((i=t>>>16)!=0){t=i;e+=16}if((i=t>>8)!=0){t=i;e+=8}if((i=t>>4)!=0){t=i;e+=4}if((i=t>>2)!=0){t=i;e+=2}if((i=t>>1)!=0){t=i;e+=1}return e}function bnBitLength(){if(this.t<=0)return 0;return this.DB*(this.t-1)+nbits(this[this.t-1]^this.s&this.DM)}function bnpDLShiftTo(t,e){var i;for(i=this.t-1;i>=0;--i)e[i+t]=this[i];for(i=t-1;i>=0;--i)e[i]=0;e.t=this.t+t;e.s=this.s}function bnpDRShiftTo(t,e){for(var i=t;i<this.t;++i)e[i-t]=this[i];e.t=Math.max(this.t-t,0);e.s=this.s}function bnpLShiftTo(t,e){var i=t%this.DB;var r=this.DB-i;var n=(1<<r)-1;var s=Math.floor(t/this.DB),o=this.s<<i&this.DM,u;for(u=this.t-1;u>=0;--u){e[u+s+1]=this[u]>>r|o;o=(this[u]&n)<<i}for(u=s-1;u>=0;--u)e[u]=0;e[s]=o;e.t=this.t+s+1;e.s=this.s;e.clamp()}function bnpRShiftTo(t,e){e.s=this.s;var i=Math.floor(t/this.DB);if(i>=this.t){e.t=0;return}var r=t%this.DB;var n=this.DB-r;var s=(1<<r)-1;e[0]=this[i]>>r;for(var o=i+1;o<this.t;++o){e[o-i-1]|=(this[o]&s)<<n;e[o-i]=this[o]>>r}if(r>0)e[this.t-i-1]|=(this.s&s)<<n;e.t=this.t-i;e.clamp()}function bnpSubTo(t,e){var i=0,r=0,n=Math.min(t.t,this.t);while(i<n){r+=this[i]-t[i];e[i++]=r&this.DM;r>>=this.DB}if(t.t<this.t){r-=t.s;while(i<this.t){r+=this[i];e[i++]=r&this.DM;r>>=this.DB}r+=this.s}else{r+=this.s;while(i<t.t){r-=t[i];e[i++]=r&this.DM;r>>=this.DB}r-=t.s}e.s=r<0?-1:0;if(r<-1)e[i++]=this.DV+r;else if(r>0)e[i++]=r;e.t=i;e.clamp()}function bnpMultiplyTo(t,e){var i=this.abs(),r=t.abs();var n=i.t;e.t=n+r.t;while(--n>=0)e[n]=0;for(n=0;n<r.t;++n)e[n+i.t]=i.am(0,r[n],e,n,0,i.t);e.s=0;e.clamp();if(this.s!=t.s)BigInteger.ZERO.subTo(e,e)}function bnpSquareTo(t){var e=this.abs();var i=t.t=2*e.t;while(--i>=0)t[i]=0;for(i=0;i<e.t-1;++i){var r=e.am(i,e[i],t,2*i,0,1);if((t[i+e.t]+=e.am(i+1,2*e[i],t,2*i+1,r,e.t-i-1))>=e.DV){t[i+e.t]-=e.DV;t[i+e.t+1]=1}}if(t.t>0)t[t.t-1]+=e.am(i,e[i],t,2*i,0,1);t.s=0;t.clamp()}function bnpDivRemTo(t,e,i){var r=t.abs();if(r.t<=0)return;var n=this.abs();if(n.t<r.t){if(e!=null)e.fromInt(0);if(i!=null)this.copyTo(i);return}if(i==null)i=nbi();var s=nbi(),o=this.s,u=t.s;var a=this.DB-nbits(r[r.t-1]);if(a>0){r.lShiftTo(a,s);n.lShiftTo(a,i)}else{r.copyTo(s);n.copyTo(i)}var h=s.t;var p=s[h-1];if(p==0)return;var f=p*(1<<this.F1)+(h>1?s[h-2]>>this.F2:0);var l=this.FV/f,c=(1<<this.F1)/f,g=1<<this.F2;var F=i.t,v=F-h,y=e==null?nbi():e;s.dlShiftTo(v,y);if(i.compareTo(y)>=0){i[i.t++]=1;i.subTo(y,i)}BigInteger.ONE.dlShiftTo(h,y);y.subTo(s,s);while(s.t<h)s[s.t++]=0;while(--v>=0){var B=i[--F]==p?this.DM:Math.floor(i[F]*l+(i[F-1]+g)*c);if((i[F]+=s.am(0,B,i,v,0,h))<B){s.dlShiftTo(v,y);i.subTo(y,i);while(i[F]<--B)i.subTo(y,i)}}if(e!=null){i.drShiftTo(h,e);if(o!=u)BigInteger.ZERO.subTo(e,e)}i.t=h;i.clamp();if(a>0)i.rShiftTo(a,i);if(o<0)BigInteger.ZERO.subTo(i,i)}function bnMod(t){var e=nbi();this.abs().divRemTo(t,null,e);if(this.s<0&&e.compareTo(BigInteger.ZERO)>0)t.subTo(e,e);return e}function Classic(t){this.m=t}function cConvert(t){if(t.s<0||t.compareTo(this.m)>=0)return t.mod(this.m);else return t}function cRevert(t){return t}function cReduce(t){t.divRemTo(this.m,null,t)}function cMulTo(t,e,i){t.multiplyTo(e,i);this.reduce(i)}function cSqrTo(t,e){t.squareTo(e);this.reduce(e)}Classic.prototype.convert=cConvert;Classic.prototype.revert=cRevert;Classic.prototype.reduce=cReduce;Classic.prototype.mulTo=cMulTo;Classic.prototype.sqrTo=cSqrTo;function bnpInvDigit(){if(this.t<1)return 0;var t=this[0];if((t&1)==0)return 0;var e=t&3;e=e*(2-(t&15)*e)&15;e=e*(2-(t&255)*e)&255;e=e*(2-((t&65535)*e&65535))&65535;e=e*(2-t*e%this.DV)%this.DV;return e>0?this.DV-e:-e}function Montgomery(t){this.m=t;this.mp=t.invDigit();this.mpl=this.mp&32767;this.mph=this.mp>>15;this.um=(1<<t.DB-15)-1;this.mt2=2*t.t}function montConvert(t){var e=nbi();t.abs().dlShiftTo(this.m.t,e);e.divRemTo(this.m,null,e);if(t.s<0&&e.compareTo(BigInteger.ZERO)>0)this.m.subTo(e,e);return e}function montRevert(t){var e=nbi();t.copyTo(e);this.reduce(e);return e}function montReduce(t){while(t.t<=this.mt2)t[t.t++]=0;for(var e=0;e<this.m.t;++e){var i=t[e]&32767;var r=i*this.mpl+((i*this.mph+(t[e]>>15)*this.mpl&this.um)<<15)&t.DM;i=e+this.m.t;t[i]+=this.m.am(0,r,t,e,0,this.m.t);while(t[i]>=t.DV){t[i]-=t.DV;t[++i]++}}t.clamp();t.drShiftTo(this.m.t,t);if(t.compareTo(this.m)>=0)t.subTo(this.m,t)}function montSqrTo(t,e){t.squareTo(e);this.reduce(e)}function montMulTo(t,e,i){t.multiplyTo(e,i);this.reduce(i)}Montgomery.prototype.convert=montConvert;Montgomery.prototype.revert=montRevert;Montgomery.prototype.reduce=montReduce;Montgomery.prototype.mulTo=montMulTo;Montgomery.prototype.sqrTo=montSqrTo;function bnpIsEven(){return(this.t>0?this[0]&1:this.s)==0}function bnpExp(t,e){if(t>4294967295||t<1)return BigInteger.ONE;var i=nbi(),r=nbi(),n=e.convert(this),s=nbits(t)-1;n.copyTo(i);while(--s>=0){e.sqrTo(i,r);if((t&1<<s)>0)e.mulTo(r,n,i);else{var o=i;i=r;r=o}}return e.revert(i)}function bnModPowInt(t,e){var i;if(t<256||e.isEven())i=new Classic(e);else i=new Montgomery(e);return this.exp(t,i)}BigInteger.prototype.copyTo=bnpCopyTo;BigInteger.prototype.fromInt=bnpFromInt;BigInteger.prototype.fromString=bnpFromString;BigInteger.prototype.clamp=bnpClamp;BigInteger.prototype.dlShiftTo=bnpDLShiftTo;BigInteger.prototype.drShiftTo=bnpDRShiftTo;BigInteger.prototype.lShiftTo=bnpLShiftTo;BigInteger.prototype.rShiftTo=bnpRShiftTo;BigInteger.prototype.subTo=bnpSubTo;BigInteger.prototype.multiplyTo=bnpMultiplyTo;BigInteger.prototype.squareTo=bnpSquareTo;BigInteger.prototype.divRemTo=bnpDivRemTo;BigInteger.prototype.invDigit=bnpInvDigit;BigInteger.prototype.isEven=bnpIsEven;BigInteger.prototype.exp=bnpExp;BigInteger.prototype.toString=bnToString;BigInteger.prototype.negate=bnNegate;BigInteger.prototype.abs=bnAbs;BigInteger.prototype.compareTo=bnCompareTo;BigInteger.prototype.bitLength=bnBitLength;BigInteger.prototype.mod=bnMod;BigInteger.prototype.modPowInt=bnModPowInt;BigInteger.ZERO=nbv(0);BigInteger.ONE=nbv(1);function bnClone(){var t=nbi();this.copyTo(t);return t}function bnIntValue(){if(this.s<0){if(this.t==1)return this[0]-this.DV;else if(this.t==0)return-1}else if(this.t==1)return this[0];else if(this.t==0)return 0;return(this[1]&(1<<32-this.DB)-1)<<this.DB|this[0]}function bnByteValue(){return this.t==0?this.s:this[0]<<24>>24}function bnShortValue(){return this.t==0?this.s:this[0]<<16>>16}function bnpChunkSize(t){return Math.floor(Math.LN2*this.DB/Math.log(t))}function bnSigNum(){if(this.s<0)return-1;else if(this.t<=0||this.t==1&&this[0]<=0)return 0;else return 1}function bnpToRadix(t){if(t==null)t=10;if(this.signum()==0||t<2||t>36)return"0";var e=this.chunkSize(t);var i=Math.pow(t,e);var r=nbv(i),n=nbi(),s=nbi(),o="";this.divRemTo(r,n,s);while(n.signum()>0){o=(i+s.intValue()).toString(t).substr(1)+o;n.divRemTo(r,n,s)}return s.intValue().toString(t)+o}function bnpFromRadix(t,e){this.fromInt(0);if(e==null)e=10;var i=this.chunkSize(e);var r=Math.pow(e,i),n=false,s=0,o=0;for(var u=0;u<t.length;++u){var a=intAt(t,u);if(a<0){if(t.charAt(u)=="-"&&this.signum()==0)n=true;continue}o=e*o+a;if(++s>=i){this.dMultiply(r);this.dAddOffset(o,0);s=0;o=0}}if(s>0){this.dMultiply(Math.pow(e,s));this.dAddOffset(o,0)}if(n)BigInteger.ZERO.subTo(this,this)}function bnpFromNumber(t,e,i){if("number"==typeof e){if(t<2)this.fromInt(1);else{this.fromNumber(t,i);if(!this.testBit(t-1))this.bitwiseTo(BigInteger.ONE.shiftLeft(t-1),op_or,this);if(this.isEven())this.dAddOffset(1,0);while(!this.isProbablePrime(e)){this.dAddOffset(2,0);if(this.bitLength()>t)this.subTo(BigInteger.ONE.shiftLeft(t-1),this)}}}else{var r=new Array,n=t&7;r.length=(t>>3)+1;e.nextBytes(r);if(n>0)r[0]&=(1<<n)-1;else r[0]=0;this.fromString(r,256)}}function bnToByteArray(){var t=this.t,e=new Array;e[0]=this.s;var i=this.DB-t*this.DB%8,r,n=0;if(t-->0){if(i<this.DB&&(r=this[t]>>i)!=(this.s&this.DM)>>i)e[n++]=r|this.s<<this.DB-i;while(t>=0){if(i<8){r=(this[t]&(1<<i)-1)<<8-i;r|=this[--t]>>(i+=this.DB-8)}else{r=this[t]>>(i-=8)&255;if(i<=0){i+=this.DB;--t}}if((r&128)!=0)r|=-256;if(n==0&&(this.s&128)!=(r&128))++n;if(n>0||r!=this.s)e[n++]=r}}return e}function bnEquals(t){return this.compareTo(t)==0}function bnMin(t){return this.compareTo(t)<0?this:t}function bnMax(t){return this.compareTo(t)>0?this:t}function bnpBitwiseTo(t,e,i){var r,n,s=Math.min(t.t,this.t);for(r=0;r<s;++r)i[r]=e(this[r],t[r]);if(t.t<this.t){n=t.s&this.DM;for(r=s;r<this.t;++r)i[r]=e(this[r],n);i.t=this.t}else{n=this.s&this.DM;for(r=s;r<t.t;++r)i[r]=e(n,t[r]);i.t=t.t}i.s=e(this.s,t.s);i.clamp()}function op_and(t,e){return t&e}function bnAnd(t){var e=nbi();this.bitwiseTo(t,op_and,e);return e}function op_or(t,e){return t|e}function bnOr(t){var e=nbi();this.bitwiseTo(t,op_or,e);return e}function op_xor(t,e){return t^e}function bnXor(t){var e=nbi();this.bitwiseTo(t,op_xor,e);return e}function op_andnot(t,e){return t&~e}function bnAndNot(t){var e=nbi();this.bitwiseTo(t,op_andnot,e);return e}function bnNot(){var t=nbi();for(var e=0;e<this.t;++e)t[e]=this.DM&~this[e];t.t=this.t;t.s=~this.s;return t}function bnShiftLeft(t){var e=nbi();if(t<0)this.rShiftTo(-t,e);else this.lShiftTo(t,e);return e}function bnShiftRight(t){var e=nbi();if(t<0)this.lShiftTo(-t,e);else this.rShiftTo(t,e);return e}function lbit(t){if(t==0)return-1;var e=0;if((t&65535)==0){t>>=16;e+=16}if((t&255)==0){t>>=8;e+=8}if((t&15)==0){t>>=4;e+=4}if((t&3)==0){t>>=2;e+=2}if((t&1)==0)++e;return e}function bnGetLowestSetBit(){for(var t=0;t<this.t;++t)if(this[t]!=0)return t*this.DB+lbit(this[t]);if(this.s<0)return this.t*this.DB;return-1}function cbit(t){var e=0;while(t!=0){t&=t-1;++e}return e}function bnBitCount(){var t=0,e=this.s&this.DM;for(var i=0;i<this.t;++i)t+=cbit(this[i]^e);return t}function bnTestBit(t){var e=Math.floor(t/this.DB);if(e>=this.t)return this.s!=0;return(this[e]&1<<t%this.DB)!=0}function bnpChangeBit(t,e){var i=BigInteger.ONE.shiftLeft(t);this.bitwiseTo(i,e,i);return i}function bnSetBit(t){return this.changeBit(t,op_or)}function bnClearBit(t){return this.changeBit(t,op_andnot)}function bnFlipBit(t){return this.changeBit(t,op_xor)}function bnpAddTo(t,e){var i=0,r=0,n=Math.min(t.t,this.t);while(i<n){r+=this[i]+t[i];e[i++]=r&this.DM;r>>=this.DB}if(t.t<this.t){r+=t.s;while(i<this.t){r+=this[i];e[i++]=r&this.DM;r>>=this.DB}r+=this.s}else{r+=this.s;while(i<t.t){r+=t[i];e[i++]=r&this.DM;r>>=this.DB}r+=t.s}e.s=r<0?-1:0;if(r>0)e[i++]=r;else if(r<-1)e[i++]=this.DV+r;e.t=i;e.clamp()}function bnAdd(t){var e=nbi();this.addTo(t,e);return e}function bnSubtract(t){var e=nbi();this.subTo(t,e);return e}function bnMultiply(t){var e=nbi();this.multiplyTo(t,e);return e}function bnSquare(){var t=nbi();this.squareTo(t);return t}function bnDivide(t){var e=nbi();this.divRemTo(t,e,null);return e}function bnRemainder(t){var e=nbi();this.divRemTo(t,null,e);return e}function bnDivideAndRemainder(t){var e=nbi(),i=nbi();this.divRemTo(t,e,i);return new Array(e,i)}function bnpDMultiply(t){this[this.t]=this.am(0,t-1,this,0,0,this.t);++this.t;this.clamp()}function bnpDAddOffset(t,e){if(t==0)return;while(this.t<=e)this[this.t++]=0;this[e]+=t;while(this[e]>=this.DV){this[e]-=this.DV;if(++e>=this.t)this[this.t++]=0;++this[e]}}function NullExp(){}function nNop(t){return t}function nMulTo(t,e,i){t.multiplyTo(e,i)}function nSqrTo(t,e){t.squareTo(e)}NullExp.prototype.convert=nNop;NullExp.prototype.revert=nNop;NullExp.prototype.mulTo=nMulTo;NullExp.prototype.sqrTo=nSqrTo;function bnPow(t){return this.exp(t,new NullExp)}function bnpMultiplyLowerTo(t,e,i){var r=Math.min(this.t+t.t,e);i.s=0;i.t=r;while(r>0)i[--r]=0;var n;for(n=i.t-this.t;r<n;++r)i[r+this.t]=this.am(0,t[r],i,r,0,this.t);for(n=Math.min(t.t,e);r<n;++r)this.am(0,t[r],i,r,0,e-r);i.clamp()}function bnpMultiplyUpperTo(t,e,i){--e;var r=i.t=this.t+t.t-e;i.s=0;while(--r>=0)i[r]=0;for(r=Math.max(e-this.t,0);r<t.t;++r)i[this.t+r-e]=this.am(e-r,t[r],i,0,0,this.t+r-e);i.clamp();i.drShiftTo(1,i)}function Barrett(t){this.r2=nbi();this.q3=nbi();BigInteger.ONE.dlShiftTo(2*t.t,this.r2);this.mu=this.r2.divide(t);this.m=t}function barrettConvert(t){if(t.s<0||t.t>2*this.m.t)return t.mod(this.m);else if(t.compareTo(this.m)<0)return t;else{var e=nbi();t.copyTo(e);this.reduce(e);return e}}function barrettRevert(t){return t}function barrettReduce(t){t.drShiftTo(this.m.t-1,this.r2);if(t.t>this.m.t+1){t.t=this.m.t+1;t.clamp()}this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);while(t.compareTo(this.r2)<0)t.dAddOffset(1,this.m.t+1);t.subTo(this.r2,t);while(t.compareTo(this.m)>=0)t.subTo(this.m,t)}function barrettSqrTo(t,e){t.squareTo(e);this.reduce(e)}function barrettMulTo(t,e,i){t.multiplyTo(e,i);this.reduce(i)}Barrett.prototype.convert=barrettConvert;Barrett.prototype.revert=barrettRevert;Barrett.prototype.reduce=barrettReduce;Barrett.prototype.mulTo=barrettMulTo;Barrett.prototype.sqrTo=barrettSqrTo;function bnModPow(t,e){var i=t.bitLength(),r,n=nbv(1),s;if(i<=0)return n;else if(i<18)r=1;else if(i<48)r=3;else if(i<144)r=4;else if(i<768)r=5;else r=6;if(i<8)s=new Classic(e);else if(e.isEven())s=new Barrett(e);else s=new Montgomery(e);var o=new Array,u=3,a=r-1,h=(1<<r)-1;o[1]=s.convert(this);if(r>1){var p=nbi();s.sqrTo(o[1],p);while(u<=h){o[u]=nbi();s.mulTo(p,o[u-2],o[u]);u+=2}}var f=t.t-1,l,c=true,g=nbi(),F;i=nbits(t[f])-1;while(f>=0){if(i>=a)l=t[f]>>i-a&h;else{l=(t[f]&(1<<i+1)-1)<<a-i;if(f>0)l|=t[f-1]>>this.DB+i-a}u=r;while((l&1)==0){l>>=1;--u}if((i-=u)<0){i+=this.DB;--f}if(c){o[l].copyTo(n);c=false}else{while(u>1){s.sqrTo(n,g);s.sqrTo(g,n);u-=2}if(u>0)s.sqrTo(n,g);else{F=n;n=g;g=F}s.mulTo(g,o[l],n)}while(f>=0&&(t[f]&1<<i)==0){s.sqrTo(n,g);F=n;n=g;g=F;if(--i<0){i=this.DB-1;--f}}}return s.revert(n)}function bnGCD(t){var e=this.s<0?this.negate():this.clone();var i=t.s<0?t.negate():t.clone();if(e.compareTo(i)<0){var r=e;e=i;i=r}var n=e.getLowestSetBit(),s=i.getLowestSetBit();if(s<0)return e;if(n<s)s=n;if(s>0){e.rShiftTo(s,e);i.rShiftTo(s,i)}while(e.signum()>0){if((n=e.getLowestSetBit())>0)e.rShiftTo(n,e);if((n=i.getLowestSetBit())>0)i.rShiftTo(n,i);if(e.compareTo(i)>=0){e.subTo(i,e);e.rShiftTo(1,e)}else{i.subTo(e,i);i.rShiftTo(1,i)}}if(s>0)i.lShiftTo(s,i);return i}function bnpModInt(t){if(t<=0)return 0;var e=this.DV%t,i=this.s<0?t-1:0;if(this.t>0)if(e==0)i=this[0]%t;else for(var r=this.t-1;r>=0;--r)i=(e*i+this[r])%t;return i}function bnModInverse(t){var e=t.isEven();if(this.isEven()&&e||t.signum()==0)return BigInteger.ZERO;var i=t.clone(),r=this.clone();var n=nbv(1),s=nbv(0),o=nbv(0),u=nbv(1);while(i.signum()!=0){while(i.isEven()){i.rShiftTo(1,i);if(e){if(!n.isEven()||!s.isEven()){n.addTo(this,n);s.subTo(t,s)}n.rShiftTo(1,n)}else if(!s.isEven())s.subTo(t,s);s.rShiftTo(1,s)}while(r.isEven()){r.rShiftTo(1,r);if(e){if(!o.isEven()||!u.isEven()){o.addTo(this,o);u.subTo(t,u)}o.rShiftTo(1,o)}else if(!u.isEven())u.subTo(t,u);u.rShiftTo(1,u)}if(i.compareTo(r)>=0){i.subTo(r,i);if(e)n.subTo(o,n);s.subTo(u,s)}else{r.subTo(i,r);if(e)o.subTo(n,o);u.subTo(s,u)}}if(r.compareTo(BigInteger.ONE)!=0)return BigInteger.ZERO;if(u.compareTo(t)>=0)return u.subtract(t);if(u.signum()<0)u.addTo(t,u);else return u;if(u.signum()<0)return u.add(t);else return u}var lowprimes=[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];var lplim=(1<<26)/lowprimes[lowprimes.length-1];function bnIsProbablePrime(t){var e,i=this.abs();if(i.t==1&&i[0]<=lowprimes[lowprimes.length-1]){for(e=0;e<lowprimes.length;++e)if(i[0]==lowprimes[e])return true;return false}if(i.isEven())return false;e=1;while(e<lowprimes.length){var r=lowprimes[e],n=e+1;while(n<lowprimes.length&&r<lplim)r*=lowprimes[n++];r=i.modInt(r);while(e<n)if(r%lowprimes[e++]==0)return false}return i.millerRabin(t)}function bnpMillerRabin(t){var e=this.subtract(BigInteger.ONE);var i=e.getLowestSetBit();if(i<=0)return false;var r=e.shiftRight(i);t=t+1>>1;if(t>lowprimes.length)t=lowprimes.length;var n=nbi();for(var s=0;s<t;++s){n.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);var o=n.modPow(r,this);if(o.compareTo(BigInteger.ONE)!=0&&o.compareTo(e)!=0){var u=1;while(u++<i&&o.compareTo(e)!=0){o=o.modPowInt(2,this);if(o.compareTo(BigInteger.ONE)==0)return false}if(o.compareTo(e)!=0)return false}}return true}BigInteger.prototype.chunkSize=bnpChunkSize;BigInteger.prototype.toRadix=bnpToRadix;BigInteger.prototype.fromRadix=bnpFromRadix;BigInteger.prototype.fromNumber=bnpFromNumber;BigInteger.prototype.bitwiseTo=bnpBitwiseTo;BigInteger.prototype.changeBit=bnpChangeBit;BigInteger.prototype.addTo=bnpAddTo;BigInteger.prototype.dMultiply=bnpDMultiply;BigInteger.prototype.dAddOffset=bnpDAddOffset;BigInteger.prototype.multiplyLowerTo=bnpMultiplyLowerTo;BigInteger.prototype.multiplyUpperTo=bnpMultiplyUpperTo;BigInteger.prototype.modInt=bnpModInt;BigInteger.prototype.millerRabin=bnpMillerRabin;BigInteger.prototype.clone=bnClone;BigInteger.prototype.intValue=bnIntValue;BigInteger.prototype.byteValue=bnByteValue;BigInteger.prototype.shortValue=bnShortValue;BigInteger.prototype.signum=bnSigNum;BigInteger.prototype.toByteArray=bnToByteArray;BigInteger.prototype.equals=bnEquals;BigInteger.prototype.min=bnMin;BigInteger.prototype.max=bnMax;BigInteger.prototype.and=bnAnd;BigInteger.prototype.or=bnOr;BigInteger.prototype.xor=bnXor;BigInteger.prototype.andNot=bnAndNot;BigInteger.prototype.not=bnNot;BigInteger.prototype.shiftLeft=bnShiftLeft;BigInteger.prototype.shiftRight=bnShiftRight;BigInteger.prototype.getLowestSetBit=bnGetLowestSetBit;BigInteger.prototype.bitCount=bnBitCount;BigInteger.prototype.testBit=bnTestBit;BigInteger.prototype.setBit=bnSetBit;BigInteger.prototype.clearBit=bnClearBit;BigInteger.prototype.flipBit=bnFlipBit;BigInteger.prototype.add=bnAdd;BigInteger.prototype.subtract=bnSubtract;BigInteger.prototype.multiply=bnMultiply;BigInteger.prototype.divide=bnDivide;BigInteger.prototype.remainder=bnRemainder;BigInteger.prototype.divideAndRemainder=bnDivideAndRemainder;BigInteger.prototype.modPow=bnModPow;BigInteger.prototype.modInverse=bnModInverse;BigInteger.prototype.pow=bnPow;BigInteger.prototype.gcd=bnGCD;BigInteger.prototype.isProbablePrime=bnIsProbablePrime;BigInteger.prototype.square=bnSquare;function Arcfour(){this.i=0;this.j=0;this.S=new Array}function ARC4init(t){var e,i,r;for(e=0;e<256;++e)this.S[e]=e;i=0;for(e=0;e<256;++e){i=i+this.S[e]+t[e%t.length]&255;r=this.S[e];this.S[e]=this.S[i];this.S[i]=r}this.i=0;this.j=0}function ARC4next(){var t;this.i=this.i+1&255;this.j=this.j+this.S[this.i]&255;t=this.S[this.i];this.S[this.i]=this.S[this.j];this.S[this.j]=t;return this.S[t+this.S[this.i]&255]}Arcfour.prototype.init=ARC4init;Arcfour.prototype.next=ARC4next;function prng_newstate(){return new Arcfour}var rng_psize=256;var rng_state;var rng_pool;var rng_pptr;function rng_seed_int(t){rng_pool[rng_pptr++]^=t&255;rng_pool[rng_pptr++]^=t>>8&255;rng_pool[rng_pptr++]^=t>>16&255;rng_pool[rng_pptr++]^=t>>24&255;if(rng_pptr>=rng_psize)rng_pptr-=rng_psize}function rng_seed_time(){rng_seed_int((new Date).getTime())}if(rng_pool==null){rng_pool=new Array;rng_pptr=0;var t;if(navigator.appName=="Netscape"&&navigator.appVersion<"5"&&window.crypto){var z=window.crypto.random(32);for(t=0;t<z.length;++t)rng_pool[rng_pptr++]=z.charCodeAt(t)&255}while(rng_pptr<rng_psize){t=Math.floor(65536*Math.random());rng_pool[rng_pptr++]=t>>>8;rng_pool[rng_pptr++]=t&255}rng_pptr=0;rng_seed_time()}function rng_get_byte(){if(rng_state==null){rng_seed_time();rng_state=prng_newstate();rng_state.init(rng_pool);for(rng_pptr=0;rng_pptr<rng_pool.length;++rng_pptr)rng_pool[rng_pptr]=0;rng_pptr=0}return rng_state.next()}function rng_get_bytes(t){var e;for(e=0;e<t.length;++e)t[e]=rng_get_byte()}function SecureRandom(){}SecureRandom.prototype.nextBytes=rng_get_bytes;function ECFieldElementFp(t,e){this.x=e;this.q=t}function feFpEquals(t){if(t==this)return true;return this.q.equals(t.q)&&this.x.equals(t.x)}function feFpToBigInteger(){return this.x}function feFpNegate(){return new ECFieldElementFp(this.q,this.x.negate().mod(this.q))}function feFpAdd(t){return new ECFieldElementFp(this.q,this.x.add(t.toBigInteger()).mod(this.q))}function feFpSubtract(t){return new ECFieldElementFp(this.q,this.x.subtract(t.toBigInteger()).mod(this.q))}function feFpMultiply(t){return new ECFieldElementFp(this.q,this.x.multiply(t.toBigInteger()).mod(this.q))}function feFpSquare(){return new ECFieldElementFp(this.q,this.x.square().mod(this.q))}function feFpDivide(t){return new ECFieldElementFp(this.q,this.x.multiply(t.toBigInteger().modInverse(this.q)).mod(this.q))}ECFieldElementFp.prototype.equals=feFpEquals;ECFieldElementFp.prototype.toBigInteger=feFpToBigInteger;ECFieldElementFp.prototype.negate=feFpNegate;ECFieldElementFp.prototype.add=feFpAdd;ECFieldElementFp.prototype.subtract=feFpSubtract;ECFieldElementFp.prototype.multiply=feFpMultiply;ECFieldElementFp.prototype.square=feFpSquare;ECFieldElementFp.prototype.divide=feFpDivide;function ECPointFp(t,e,i,r){this.curve=t;this.x=e;this.y=i;if(r==null){this.z=BigInteger.ONE}else{this.z=r}this.zinv=null}function pointFpGetX(){if(this.zinv==null){this.zinv=this.z.modInverse(this.curve.q)}return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q))}function pointFpGetY(){if(this.zinv==null){this.zinv=this.z.modInverse(this.curve.q)}return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q))}function pointFpEquals(t){if(t==this)return true;if(this.isInfinity())return t.isInfinity();if(t.isInfinity())return this.isInfinity();var e,i;e=t.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(t.z)).mod(this.curve.q);if(!e.equals(BigInteger.ZERO))return false;i=t.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(t.z)).mod(this.curve.q);return i.equals(BigInteger.ZERO)}function pointFpIsInfinity(){if(this.x==null&&this.y==null)return true;return this.z.equals(BigInteger.ZERO)&&!this.y.toBigInteger().equals(BigInteger.ZERO)}function pointFpNegate(){return new ECPointFp(this.curve,this.x,this.y.negate(),this.z)}function pointFpAdd(t){if(this.isInfinity())return t;if(t.isInfinity())return this;var e=t.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(t.z)).mod(this.curve.q);var i=t.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(t.z)).mod(this.curve.q);if(BigInteger.ZERO.equals(i)){if(BigInteger.ZERO.equals(e)){return this.twice()}return this.curve.getInfinity()}var r=new BigInteger("3");var n=this.x.toBigInteger();var s=this.y.toBigInteger();var o=t.x.toBigInteger();var u=t.y.toBigInteger();var a=i.square();var h=a.multiply(i);var p=n.multiply(a);var f=e.square().multiply(this.z);var l=f.subtract(p.shiftLeft(1)).multiply(t.z).subtract(h).multiply(i).mod(this.curve.q);var c=p.multiply(r).multiply(e).subtract(s.multiply(h)).subtract(f.multiply(e)).multiply(t.z).add(e.multiply(h)).mod(this.curve.q);var g=h.multiply(this.z).multiply(t.z).mod(this.curve.q);return new ECPointFp(this.curve,this.curve.fromBigInteger(l),this.curve.fromBigInteger(c),g)}function pointFpTwice(){if(this.isInfinity())return this;if(this.y.toBigInteger().signum()==0)return this.curve.getInfinity();var t=new BigInteger("3");var e=this.x.toBigInteger();var i=this.y.toBigInteger();var r=i.multiply(this.z);var n=r.multiply(i).mod(this.curve.q);var s=this.curve.a.toBigInteger();var o=e.square().multiply(t);if(!BigInteger.ZERO.equals(s)){o=o.add(this.z.square().multiply(s))}o=o.mod(this.curve.q);var u=o.square().subtract(e.shiftLeft(3).multiply(n)).shiftLeft(1).multiply(r).mod(this.curve.q);var a=o.multiply(t).multiply(e).subtract(n.shiftLeft(1)).shiftLeft(2).multiply(n).subtract(o.square().multiply(o)).mod(this.curve.q);var h=r.square().multiply(r).shiftLeft(3).mod(this.curve.q);return new ECPointFp(this.curve,this.curve.fromBigInteger(u),this.curve.fromBigInteger(a),h)}function pointFpMultiply(t){if(this.isInfinity())return this;if(t.signum()==0)return this.curve.getInfinity();var e=t;var i=e.multiply(new BigInteger("3"));var r=this.negate();var n=this;var s;for(s=i.bitLength()-2;s>0;--s){n=n.twice();var o=i.testBit(s);var u=e.testBit(s);if(o!=u){n=n.add(o?this:r)}}return n}function pointFpMultiplyTwo(t,e,i){var r;if(t.bitLength()>i.bitLength())r=t.bitLength()-1;else r=i.bitLength()-1;var n=this.curve.getInfinity();var s=this.add(e);while(r>=0){n=n.twice();if(t.testBit(r)){if(i.testBit(r)){n=n.add(s)}else{n=n.add(this)}}else{if(i.testBit(r)){n=n.add(e)}}--r}return n}ECPointFp.prototype.getX=pointFpGetX;ECPointFp.prototype.getY=pointFpGetY;ECPointFp.prototype.equals=pointFpEquals;ECPointFp.prototype.isInfinity=pointFpIsInfinity;ECPointFp.prototype.negate=pointFpNegate;ECPointFp.prototype.add=pointFpAdd;ECPointFp.prototype.twice=pointFpTwice;ECPointFp.prototype.multiply=pointFpMultiply;ECPointFp.prototype.multiplyTwo=pointFpMultiplyTwo;function ECCurveFp(t,e,i){this.q=t;this.a=this.fromBigInteger(e);this.b=this.fromBigInteger(i);this.infinity=new ECPointFp(this,null,null)}function curveFpGetQ(){return this.q}function curveFpGetA(){return this.a}function curveFpGetB(){return this.b}function curveFpEquals(t){if(t==this)return true;return this.q.equals(t.q)&&this.a.equals(t.a)&&this.b.equals(t.b)}function curveFpGetInfinity(){return this.infinity}function curveFpFromBigInteger(t){return new ECFieldElementFp(this.q,t)}function curveFpDecodePointHex(t){switch(parseInt(t.substr(0,2),16)){case 0:return this.infinity;case 2:case 3:return null;case 4:case 6:case 7:var e=(t.length-2)/2;var i=t.substr(2,e);var r=t.substr(e+2,e);return new ECPointFp(this,this.fromBigInteger(new BigInteger(i,16)),this.fromBigInteger(new BigInteger(r,16)));default:return null}}ECCurveFp.prototype.getQ=curveFpGetQ;ECCurveFp.prototype.getA=curveFpGetA;ECCurveFp.prototype.getB=curveFpGetB;ECCurveFp.prototype.equals=curveFpEquals;ECCurveFp.prototype.getInfinity=curveFpGetInfinity;ECCurveFp.prototype.fromBigInteger=curveFpFromBigInteger;ECCurveFp.prototype.decodePointHex=curveFpDecodePointHex;function X9ECParameters(t,e,i,r){this.curve=t;this.g=e;this.n=i;this.h=r}function x9getCurve(){return this.curve}function x9getG(){return this.g}function x9getN(){return this.n}function x9getH(){return this.h}X9ECParameters.prototype.getCurve=x9getCurve;X9ECParameters.prototype.getG=x9getG;X9ECParameters.prototype.getN=x9getN;X9ECParameters.prototype.getH=x9getH;function fromHex(t){return new BigInteger(t,16)}function secp128r1(){var t=fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");var e=fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");var i=fromHex("E87579C11079F43DD824993C2CEE5ED3");var r=fromHex("FFFFFFFE0000000075A30D1B9038A115");var n=BigInteger.ONE;var s=new ECCurveFp(t,e,i);var o=s.decodePointHex("04"+"161FF7528B899B2D0C28607CA52C5B86"+"CF5AC8395BAFEB13C02DA292DDED7A83");return new X9ECParameters(s,o,r,n)}function secp160k1(){var t=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");var e=BigInteger.ZERO;var i=fromHex("7");var r=fromHex("0100000000000000000001B8FA16DFAB9ACA16B6B3");var n=BigInteger.ONE;var s=new ECCurveFp(t,e,i);var o=s.decodePointHex("04"+"3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"+"938CF935318FDCED6BC28286531733C3F03C4FEE");return new X9ECParameters(s,o,r,n)}function secp160r1(){var t=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");var e=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");var i=fromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");var r=fromHex("0100000000000000000001F4C8F927AED3CA752257");var n=BigInteger.ONE;var s=new ECCurveFp(t,e,i);var o=s.decodePointHex("04"+"4A96B5688EF573284664698968C38BB913CBFC82"+"23A628553168947D59DCC912042351377AC5FB32");return new X9ECParameters(s,o,r,n)}function secp192k1(){var t=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");var e=BigInteger.ZERO;var i=fromHex("3");var r=fromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");var n=BigInteger.ONE;var s=new ECCurveFp(t,e,i);var o=s.decodePointHex("04"+"DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"+"9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D");return new X9ECParameters(s,o,r,n)}function secp192r1(){var t=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");var e=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");var i=fromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");var r=fromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
var n=BigInteger.ONE;var s=new ECCurveFp(t,e,i);var o=s.decodePointHex("04"+"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"+"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");return new X9ECParameters(s,o,r,n)}function secp224r1(){var t=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");var e=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");var i=fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");var r=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");var n=BigInteger.ONE;var s=new ECCurveFp(t,e,i);var o=s.decodePointHex("04"+"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"+"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");return new X9ECParameters(s,o,r,n)}function secp256k1(){var t=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");var e=BigInteger.ZERO;var i=fromHex("7");var r=fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");var n=BigInteger.ONE;var s=new ECCurveFp(t,e,i);var o=s.decodePointHex("04"+"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"+"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");return new X9ECParameters(s,o,r,n)}function secp256r1(){var t=fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");var e=fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");var i=fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");var r=fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");var n=BigInteger.ONE;var s=new ECCurveFp(t,e,i);var o=s.decodePointHex("04"+"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"+"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");return new X9ECParameters(s,o,r,n)}function getSECCurveByName(t){if(t=="secp128r1")return secp128r1();if(t=="secp160k1")return secp160k1();if(t=="secp160r1")return secp160r1();if(t=="secp192k1")return secp192k1();if(t=="secp192r1")return secp192r1();if(t=="secp224r1")return secp224r1();if(t=="secp256k1")return secp256k1();if(t=="secp256r1")return secp256r1();return null}(function(){var t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";var e=window.Crypto={};var i=e.util={rotl:function(t,e){return t<<e|t>>>32-e},rotr:function(t,e){return t<<32-e|t>>>e},endian:function(t){if(t.constructor==Number){return i.rotl(t,8)&16711935|i.rotl(t,24)&4278255360}for(var e=0;e<t.length;e++)t[e]=i.endian(t[e]);return t},randomBytes:function(t){for(var e=[];t>0;t--)e.push(Math.floor(Math.random()*256));return e},bytesToWords:function(t){for(var e=[],i=0,r=0;i<t.length;i++,r+=8)e[r>>>5]|=t[i]<<24-r%32;return e},wordsToBytes:function(t){for(var e=[],i=0;i<t.length*32;i+=8)e.push(t[i>>>5]>>>24-i%32&255);return e},bytesToHex:function(t){for(var e=[],i=0;i<t.length;i++){e.push((t[i]>>>4).toString(16));e.push((t[i]&15).toString(16))}return e.join("")},hexToBytes:function(t){for(var e=[],i=0;i<t.length;i+=2)e.push(parseInt(t.substr(i,2),16));return e},bytesToBase64:function(e){if(typeof btoa=="function")return btoa(s.bytesToString(e));for(var i=[],r=0;r<e.length;r+=3){var n=e[r]<<16|e[r+1]<<8|e[r+2];for(var o=0;o<4;o++){if(r*8+o*6<=e.length*8)i.push(t.charAt(n>>>6*(3-o)&63));else i.push("=")}}return i.join("")},base64ToBytes:function(e){if(typeof atob=="function")return s.stringToBytes(atob(e));e=e.replace(/[^A-Z0-9+\/]/gi,"");for(var i=[],r=0,n=0;r<e.length;n=++r%4){if(n==0)continue;i.push((t.indexOf(e.charAt(r-1))&Math.pow(2,-2*n+8)-1)<<n*2|t.indexOf(e.charAt(r))>>>6-n*2)}return i}};e.mode={};var r=e.charenc={};var n=r.UTF8={stringToBytes:function(t){return s.stringToBytes(unescape(encodeURIComponent(t)))},bytesToString:function(t){return decodeURIComponent(escape(s.bytesToString(t)))}};var s=r.Binary={stringToBytes:function(t){for(var e=[],i=0;i<t.length;i++)e.push(t.charCodeAt(i));return e},bytesToString:function(t){for(var e=[],i=0;i<t.length;i++)e.push(String.fromCharCode(t[i]));return e.join("")}}})();(function(){var t=Crypto,e=t.util,i=t.charenc,r=i.UTF8,n=i.Binary;var s=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];var o=t.SHA256=function(t,i){var r=e.wordsToBytes(o._sha256(t));return i&&i.asBytes?r:i&&i.asString?n.bytesToString(r):e.bytesToHex(r)};o._sha256=function(t){if(t.constructor==String)t=r.stringToBytes(t);var i=e.bytesToWords(t),n=t.length*8,o=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],u=[],a,h,p,f,l,c,g,F,v,y,B,m;i[n>>5]|=128<<24-n%32;i[(n+64>>9<<4)+15]=n;for(var v=0;v<i.length;v+=16){a=o[0];h=o[1];p=o[2];f=o[3];l=o[4];c=o[5];g=o[6];F=o[7];for(var y=0;y<64;y++){if(y<16)u[y]=i[y+v];else{var d=u[y-15],b=u[y-2],I=(d<<25|d>>>7)^(d<<14|d>>>18)^d>>>3,E=(b<<15|b>>>17)^(b<<13|b>>>19)^b>>>10;u[y]=I+(u[y-7]>>>0)+E+(u[y-16]>>>0)}var T=l&c^~l&g,C=a&h^a&p^h&p,w=(a<<30|a>>>2)^(a<<19|a>>>13)^(a<<10|a>>>22),P=(l<<26|l>>>6)^(l<<21|l>>>11)^(l<<7|l>>>25);B=(F>>>0)+P+T+s[y]+(u[y]>>>0);m=w+C;F=g;g=c;c=l;l=f+B;f=p;p=h;h=a;a=B+m}o[0]+=a;o[1]+=h;o[2]+=p;o[3]+=f;o[4]+=l;o[5]+=c;o[6]+=g;o[7]+=F}return o};o._blocksize=16})();(function(){var t=Crypto,e=t.util,i=t.charenc,r=i.UTF8,n=i.Binary;e.bytesToLWords=function(t){var e=Array(t.length>>2);for(var i=0;i<e.length;i++)e[i]=0;for(var i=0;i<t.length*8;i+=8)e[i>>5]|=(t[i/8]&255)<<i%32;return e};e.lWordsToBytes=function(t){var e=[];for(var i=0;i<t.length*32;i+=8)e.push(t[i>>5]>>>i%32&255);return e};var s=t.RIPEMD160=function(t,i){var r=e.lWordsToBytes(s._rmd160(t));return i&&i.asBytes?r:i&&i.asString?n.bytesToString(r):e.bytesToHex(r)};s._rmd160=function(t){if(t.constructor==String)t=r.stringToBytes(t);var i=e.bytesToLWords(t),n=t.length*8;i[n>>5]|=128<<n%32;i[(n+64>>>9<<4)+14]=n;var s=1732584193;var F=4023233417;var v=2562383102;var y=271733878;var B=3285377520;for(var m=0;m<i.length;m+=16){var d;var b=s,I=F,E=v,T=y,C=B;var w=s,P=F,O=v,A=y,S=B;for(var _=0;_<=79;++_){d=c(b,o(_,I,E,T));d=c(d,i[m+h[_]]);d=c(d,u(_));d=c(g(d,f[_]),C);b=C;C=T;T=g(E,10);E=I;I=d;d=c(w,o(79-_,P,O,A));d=c(d,i[m+p[_]]);d=c(d,a(_));d=c(g(d,l[_]),S);w=S;S=A;A=g(O,10);O=P;P=d}d=c(F,c(E,A));F=c(v,c(T,S));v=c(y,c(C,w));y=c(B,c(b,P));B=c(s,c(I,O));s=d}return[s,F,v,y,B]};function o(t,e,i,r){return 0<=t&&t<=15?e^i^r:16<=t&&t<=31?e&i|~e&r:32<=t&&t<=47?(e|~i)^r:48<=t&&t<=63?e&r|i&~r:64<=t&&t<=79?e^(i|~r):"rmd160_f: j out of range"}function u(t){return 0<=t&&t<=15?0:16<=t&&t<=31?1518500249:32<=t&&t<=47?1859775393:48<=t&&t<=63?2400959708:64<=t&&t<=79?2840853838:"rmd160_K1: j out of range"}function a(t){return 0<=t&&t<=15?1352829926:16<=t&&t<=31?1548603684:32<=t&&t<=47?1836072691:48<=t&&t<=63?2053994217:64<=t&&t<=79?0:"rmd160_K2: j out of range"}var h=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];var p=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];var f=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];var l=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];function c(t,e){var i=(t&65535)+(e&65535);var r=(t>>16)+(e>>16)+(i>>16);return r<<16|i&65535}function g(t,e){return t<<e|t>>>32-e}})();var EventEmitter=function(){};EventEmitter.prototype.on=function(t,e,i){if(!i)i=this;if(!this._listeners)this._listeners={};if(!this._listeners[t])this._listeners[t]=[];if(!this._unbinders)this._unbinders={};if(!this._unbinders[t])this._unbinders[t]=[];var r=function(t){e.apply(i,[t])};this._unbinders[t].push(e);this._listeners[t].push(r)};EventEmitter.prototype.trigger=function(t,e){if(e===undefined)e={};if(!this._listeners)this._listeners={};if(!this._listeners[t])return;var i=this._listeners[t].length;while(i--)this._listeners[t][i](e)};EventEmitter.prototype.removeListener=function(t,e){if(!this._unbinders)this._unbinders={};if(!this._unbinders[t])return;var i=this._unbinders[t].length;while(i--){if(this._unbinders[t][i]===e){this._unbinders[t].splice(i,1);this._listeners[t].splice(i,1)}}};EventEmitter.augment=function(t){for(var e in EventEmitter.prototype){if(!t[e])t[e]=EventEmitter.prototype[e]}};(function(t){var e=t;if("object"!==typeof module){e.EventEmitter=EventEmitter}})("object"===typeof module?module.exports:window.Bitcoin={});BigInteger.valueOf=nbv;BigInteger.prototype.toByteArrayUnsigned=function(){var t=this.abs().toByteArray();if(t.length){if(t[0]==0){t=t.slice(1)}return t.map(function(t){return t<0?t+256:t})}else{return t}};BigInteger.fromByteArrayUnsigned=function(t){if(!t.length){return t.valueOf(0)}else if(t[0]&128){return new BigInteger([0].concat(t))}else{return new BigInteger(t)}};BigInteger.prototype.toByteArraySigned=function(){var t=this.abs().toByteArrayUnsigned();var e=this.compareTo(BigInteger.ZERO)<0;if(e){if(t[0]&128){t.unshift(128)}else{t[0]|=128}}else{if(t[0]&128){t.unshift(0)}}return t};BigInteger.fromByteArraySigned=function(t){if(t[0]&128){t[0]&=127;return BigInteger.fromByteArrayUnsigned(t).negate()}else{return BigInteger.fromByteArrayUnsigned(t)}};var names=["log","debug","info","warn","error","assert","dir","dirxml","group","groupEnd","time","timeEnd","count","trace","profile","profileEnd"];if("undefined"==typeof window.console)window.console={};for(var i=0;i<names.length;++i)if("undefined"==typeof window.console[names[i]])window.console[names[i]]=function(){};Bitcoin.Util={isArray:Array.isArray||function(t){return Object.prototype.toString.call(t)==="[object Array]"},makeFilledArray:function(t,e){var i=[];var r=0;while(r<t){i[r++]=e}return i},numToVarInt:function(t){if(t<253){return[t]}else if(t<=1<<16){return[253,t>>>8,t&255]}else if(t<=1<<32){return[254].concat(Crypto.util.wordsToBytes([t]))}else{return[255].concat(Crypto.util.wordsToBytes([t>>>32,t]))}},valueToBigInt:function(t){if(t instanceof BigInteger)return t;return BigInteger.fromByteArrayUnsigned(t)},formatValue:function(t){var e=this.valueToBigInt(t).toString();var i=e.length>8?e.substr(0,e.length-8):"0";var r=e.length>8?e.substr(e.length-8):e;while(r.length<8)r="0"+r;r=r.replace(/0*$/,"");while(r.length<2)r+="0";return i+"."+r},parseValue:function(t){var e=t.split(".");var i=e[0];var r=e[1]||"0";while(r.length<8)r+="0";r=r.replace(/^0+/g,"");var n=BigInteger.valueOf(parseInt(i));n=n.multiply(BigInteger.valueOf(1e8));n=n.add(BigInteger.valueOf(parseInt(r)));return n},sha256ripe160:function(t){return Crypto.RIPEMD160(Crypto.SHA256(t,{asBytes:true}),{asBytes:true})}};for(var i in Crypto.util){if(Crypto.util.hasOwnProperty(i)){Bitcoin.Util[i]=Crypto.util[i]}}(function(t){t.Base58={alphabet:"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",validRegex:/^[1-9A-HJ-NP-Za-km-z]+$/,base:BigInteger.valueOf(58),encode:function(t){var i=BigInteger.fromByteArrayUnsigned(t);var r=[];while(i.compareTo(e.base)>=0){var n=i.mod(e.base);r.unshift(e.alphabet[n.intValue()]);i=i.subtract(n).divide(e.base)}r.unshift(e.alphabet[i.intValue()]);for(var s=0;s<t.length;s++){if(t[s]==0){r.unshift(e.alphabet[0])}else break}return r.join("")},decode:function(t){var i=BigInteger.valueOf(0);var r=0;for(var n=t.length-1;n>=0;n--){var s=e.alphabet.indexOf(t[n]);if(s<0){throw"Invalid character"}i=i.add(BigInteger.valueOf(s).multiply(e.base.pow(t.length-1-n)));if(t[n]=="1")r++;else r=0}var o=i.toByteArrayUnsigned();while(r-->0)o.unshift(0);return o}};var e=t.Base58})("undefined"!=typeof Bitcoin?Bitcoin:module.exports);Bitcoin.Address=function(t){if("string"==typeof t){t=Bitcoin.Address.decodeString(t)}this.hash=t;this.version=0};Bitcoin.Address.prototype.toString=function(){var t=this.hash.slice(0);t.unshift(this.version);var e=Crypto.SHA256(Crypto.SHA256(t,{asBytes:true}),{asBytes:true});var i=t.concat(e.slice(0,4));return Bitcoin.Base58.encode(i)};Bitcoin.Address.prototype.getHashBase64=function(){return Crypto.util.bytesToBase64(this.hash)};Bitcoin.Address.decodeString=function(t){var e=Bitcoin.Base58.decode(t);var i=e.slice(0,21);var r=Crypto.SHA256(Crypto.SHA256(i,{asBytes:true}),{asBytes:true});if(r[0]!=e[21]||r[1]!=e[22]||r[2]!=e[23]||r[3]!=e[24]){throw"Checksum validation failed!"}var n=i.shift();if(n!=0){throw"Version "+n+" not supported!"}return i};function integerToBytes(t,e){var i=t.toByteArrayUnsigned();if(e<i.length){i=i.slice(i.length-e)}else while(e>i.length){i.unshift(0)}return i}ECFieldElementFp.prototype.getByteLength=function(){return Math.floor((this.toBigInteger().bitLength()+7)/8)};ECPointFp.prototype.getEncoded=function(t){var e=this.getX().toBigInteger();var i=this.getY().toBigInteger();var r=integerToBytes(e,32);if(t){if(i.isEven()){r.unshift(2)}else{r.unshift(3)}}else{r.unshift(4);r=r.concat(integerToBytes(i,32))}return r};ECPointFp.decodeFrom=function(t,e){var i=e[0];var r=e.length-1;var n=e.slice(1,1+r/2);var s=e.slice(1+r/2,1+r);n.unshift(0);s.unshift(0);var o=new BigInteger(n);var u=new BigInteger(s);return new ECPointFp(t,t.fromBigInteger(o),t.fromBigInteger(u))};ECPointFp.prototype.add2D=function(t){if(this.isInfinity())return t;if(t.isInfinity())return this;if(this.x.equals(t.x)){if(this.y.equals(t.y)){return this.twice()}return this.curve.getInfinity()}var e=t.x.subtract(this.x);var i=t.y.subtract(this.y);var r=i.divide(e);var n=r.square().subtract(this.x).subtract(t.x);var s=r.multiply(this.x.subtract(n)).subtract(this.y);return new ECPointFp(this.curve,n,s)};ECPointFp.prototype.twice2D=function(){if(this.isInfinity())return this;if(this.y.toBigInteger().signum()==0){return this.curve.getInfinity()}var t=this.curve.fromBigInteger(BigInteger.valueOf(2));var e=this.curve.fromBigInteger(BigInteger.valueOf(3));var i=this.x.square().multiply(e).add(this.curve.a).divide(this.y.multiply(t));var r=i.square().subtract(this.x.multiply(t));var n=i.multiply(this.x.subtract(r)).subtract(this.y);return new ECPointFp(this.curve,r,n)};ECPointFp.prototype.multiply2D=function(t){if(this.isInfinity())return this;if(t.signum()==0)return this.curve.getInfinity();var e=t;var i=e.multiply(new BigInteger("3"));var r=this.negate();var n=this;var s;for(s=i.bitLength()-2;s>0;--s){n=n.twice();var o=i.testBit(s);var u=e.testBit(s);if(o!=u){n=n.add2D(o?this:r)}}return n};ECPointFp.prototype.isOnCurve=function(){var t=this.getX().toBigInteger();var e=this.getY().toBigInteger();var i=this.curve.getA().toBigInteger();var r=this.curve.getB().toBigInteger();var n=this.curve.getQ();var s=e.multiply(e).mod(n);var o=t.multiply(t).multiply(t).add(i.multiply(t)).add(r).mod(n);return s.equals(o)};ECPointFp.prototype.toString=function(){return"("+this.getX().toBigInteger().toString()+","+this.getY().toBigInteger().toString()+")"};ECPointFp.prototype.validate=function(){var t=this.curve.getQ();if(this.isInfinity()){throw new Error("Point is at infinity.")}var e=this.getX().toBigInteger();var i=this.getY().toBigInteger();if(e.compareTo(BigInteger.ONE)<0||e.compareTo(t.subtract(BigInteger.ONE))>0){throw new Error("x coordinate out of bounds")}if(i.compareTo(BigInteger.ONE)<0||i.compareTo(t.subtract(BigInteger.ONE))>0){throw new Error("y coordinate out of bounds")}if(!this.isOnCurve()){throw new Error("Point is not on the curve.")}if(this.multiply(t).isInfinity()){throw new Error("Point is not a scalar multiple of G.")}return true};function dmp(t){if(!(t instanceof BigInteger))t=t.toBigInteger();return Crypto.util.bytesToHex(t.toByteArrayUnsigned())}Bitcoin.ECDSA=function(){var t=getSECCurveByName("secp256k1");var e=new SecureRandom;var i=null;function r(t,e,i,r){var n=Math.max(e.bitLength(),r.bitLength());var s=t.add2D(i);var o=t.curve.getInfinity();for(var u=n-1;u>=0;--u){o=o.twice2D();o.z=BigInteger.ONE;if(e.testBit(u)){if(r.testBit(u)){o=o.add2D(s)}else{o=o.add2D(t)}}else{if(r.testBit(u)){o=o.add2D(i)}}}return o}var n={getBigRandom:function(t){return new BigInteger(t.bitLength(),e).mod(t.subtract(BigInteger.ONE)).add(BigInteger.ONE)},sign:function(e,i){var r=i;var s=t.getN();var o=BigInteger.fromByteArrayUnsigned(e);do{var u=n.getBigRandom(s);var a=t.getG();var h=a.multiply(u);var p=h.getX().toBigInteger().mod(s)}while(p.compareTo(BigInteger.ZERO)<=0);var f=u.modInverse(s).multiply(o.add(r.multiply(p))).mod(s);return n.serializeSig(p,f)},verify:function(e,i,r){var s,o;if(Bitcoin.Util.isArray(i)){var u=n.parseSig(i);s=u.r;o=u.s}else if("object"===typeof i&&i.r&&i.s){s=i.r;o=i.s}else{throw"Invalid value for signature"}var a;if(r instanceof ECPointFp){a=r}else if(Bitcoin.Util.isArray(r)){a=ECPointFp.decodeFrom(t.getCurve(),r)}else{throw"Invalid format for pubkey value, must be byte array or ECPointFp"}var h=BigInteger.fromByteArrayUnsigned(e);return n.verifyRaw(h,s,o,a)},verifyRaw:function(e,i,r,n){var s=t.getN();var o=t.getG();if(i.compareTo(BigInteger.ONE)<0||i.compareTo(s)>=0)return false;if(r.compareTo(BigInteger.ONE)<0||r.compareTo(s)>=0)return false;var u=r.modInverse(s);var a=e.multiply(u).mod(s);var h=i.multiply(u).mod(s);var p=o.multiply(a).add(n.multiply(h));var f=p.getX().toBigInteger().mod(s);return f.equals(i)},serializeSig:function(t,e){var i=t.toByteArraySigned();var r=e.toByteArraySigned();var n=[];n.push(2);n.push(i.length);n=n.concat(i);n.push(2);n.push(r.length);n=n.concat(r);n.unshift(n.length);n.unshift(48);return n},parseSig:function(t){var e;if(t[0]!=48)throw new Error("Signature not a valid DERSequence");e=2;if(t[e]!=2)throw new Error("First element in signature must be a DERInteger");var i=t.slice(e+2,e+2+t[e+1]);e+=2+t[e+1];if(t[e]!=2)throw new Error("Second element in signature must be a DERInteger");var r=t.slice(e+2,e+2+t[e+1]);e+=2+t[e+1];var n=BigInteger.fromByteArrayUnsigned(i);var s=BigInteger.fromByteArrayUnsigned(r);return{r:n,s:s}},parseSigCompact:function(e){if(e.length!==65){throw"Signature has the wrong length"}var i=e[0]-27;if(i<0||i>7){throw"Invalid signature type"}var r=t.getN();var n=BigInteger.fromByteArrayUnsigned(e.slice(1,33)).mod(r);var s=BigInteger.fromByteArrayUnsigned(e.slice(33,65)).mod(r);return{r:n,s:s,i:i}},recoverPubKey:function(e,s,o,u){u=u&3;var a=u&1;var h=u>>1;var p=t.getN();var f=t.getG();var l=t.getCurve();var c=l.getQ();var g=l.getA().toBigInteger();var F=l.getB().toBigInteger();if(!i){i=c.add(BigInteger.ONE).divide(BigInteger.valueOf(4))}var v=h?e.add(p):e;var y=v.multiply(v).multiply(v).add(g.multiply(v)).add(F).mod(c);var B=y.modPow(i,c);var m=B.isEven()?u%2:(u+1)%2;var d=(B.isEven()?!a:a)?B:c.subtract(B);var b=new ECPointFp(l,l.fromBigInteger(v),l.fromBigInteger(d));b.validate();var I=BigInteger.fromByteArrayUnsigned(o);var E=BigInteger.ZERO.subtract(I).mod(p);var T=e.modInverse(p);var C=r(b,s,f,E).multiply(T);C.validate();if(!n.verifyRaw(I,e,s,C)){throw"Pubkey recovery unsuccessful"}var w=new Bitcoin.ECKey;w.pub=C;return w},calcPubkeyRecoveryParam:function(t,e,i,r){for(var n=0;n<4;n++){try{var s=Bitcoin.ECDSA.recoverPubKey(e,i,r,n);if(s.getBitcoinAddress().toString()==t){return n}}catch(o){}}throw"Unable to find valid recovery factor"}};return n}();Bitcoin.ECKey=function(){var t=Bitcoin.ECDSA;var e=getSECCurveByName("secp256k1");var i=new SecureRandom;var r=function(i){if(!i){var n=e.getN();this.priv=t.getBigRandom(n)}else if(i instanceof BigInteger){this.priv=i}else if(Bitcoin.Util.isArray(i)){this.priv=BigInteger.fromByteArrayUnsigned(i)}else if("string"==typeof i){if(i.length==51&&i[0]=="5"){this.priv=BigInteger.fromByteArrayUnsigned(r.decodeString(i))}else{this.priv=BigInteger.fromByteArrayUnsigned(Crypto.util.base64ToBytes(i))}}this.compressed=!!r.compressByDefault};r.compressByDefault=false;r.prototype.setCompressed=function(t){this.compressed=!!t};r.prototype.getPub=function(){return this.getPubPoint().getEncoded(this.compressed)};r.prototype.getPubPoint=function(){if(!this.pub)this.pub=e.getG().multiply(this.priv);return this.pub};r.prototype.getPubKeyHash=function(){if(this.pubKeyHash)return this.pubKeyHash;return this.pubKeyHash=Bitcoin.Util.sha256ripe160(this.getPub())};r.prototype.getBitcoinAddress=function(){var t=this.getPubKeyHash();var e=new Bitcoin.Address(t);return e};r.prototype.getExportedPrivateKey=function(){var t=this.priv.toByteArrayUnsigned();while(t.length<32)t.unshift(0);t.unshift(128);var e=Crypto.SHA256(Crypto.SHA256(t,{asBytes:true}),{asBytes:true});var i=t.concat(e.slice(0,4));return Bitcoin.Base58.encode(i)};r.prototype.setPub=function(t){this.pub=ECPointFp.decodeFrom(e.getCurve(),t)};r.prototype.toString=function(t){if(t==="base64"){return Crypto.util.bytesToBase64(this.priv.toByteArrayUnsigned())}else{return Crypto.util.bytesToHex(this.priv.toByteArrayUnsigned())}};r.prototype.sign=function(e){return t.sign(e,this.priv)};r.prototype.verify=function(e,i){return t.verify(e,i,this.getPub())};r.decodeString=function(t){var e=Bitcoin.Base58.decode(t);var i=e.slice(0,33);var r=Crypto.SHA256(Crypto.SHA256(i,{asBytes:true}),{asBytes:true});if(r[0]!=e[33]||r[1]!=e[34]||r[2]!=e[35]||r[3]!=e[36]){throw"Checksum validation failed!"}var n=i.shift();if(n!=128){throw"Version "+n+" not supported!"}return i};return r}();(function(){var t=Bitcoin.Opcode=function(t){this.code=t};t.prototype.toString=function(){return t.reverseMap[this.code]};t.map={OP_0:0,OP_FALSE:0,OP_PUSHDATA1:76,OP_PUSHDATA2:77,OP_PUSHDATA4:78,OP_1NEGATE:79,OP_RESERVED:80,OP_1:81,OP_TRUE:81,OP_2:82,OP_3:83,OP_4:84,OP_5:85,OP_6:86,OP_7:87,OP_8:88,OP_9:89,OP_10:90,OP_11:91,OP_12:92,OP_13:93,OP_14:94,OP_15:95,OP_16:96,OP_NOP:97,OP_VER:98,OP_IF:99,OP_NOTIF:100,OP_VERIF:101,OP_VERNOTIF:102,OP_ELSE:103,OP_ENDIF:104,OP_VERIFY:105,OP_RETURN:106,OP_TOALTSTACK:107,OP_FROMALTSTACK:108,OP_2DROP:109,OP_2DUP:110,OP_3DUP:111,OP_2OVER:112,OP_2ROT:113,OP_2SWAP:114,OP_IFDUP:115,OP_DEPTH:116,OP_DROP:117,OP_DUP:118,OP_NIP:119,OP_OVER:120,OP_PICK:121,OP_ROLL:122,OP_ROT:123,OP_SWAP:124,OP_TUCK:125,OP_CAT:126,OP_SUBSTR:127,OP_LEFT:128,OP_RIGHT:129,OP_SIZE:130,OP_INVERT:131,OP_AND:132,OP_OR:133,OP_XOR:134,OP_EQUAL:135,OP_EQUALVERIFY:136,OP_RESERVED1:137,OP_RESERVED2:138,OP_1ADD:139,OP_1SUB:140,OP_2MUL:141,OP_2DIV:142,OP_NEGATE:143,OP_ABS:144,OP_NOT:145,OP_0NOTEQUAL:146,OP_ADD:147,OP_SUB:148,OP_MUL:149,OP_DIV:150,OP_MOD:151,OP_LSHIFT:152,OP_RSHIFT:153,OP_BOOLAND:154,OP_BOOLOR:155,OP_NUMEQUAL:156,OP_NUMEQUALVERIFY:157,OP_NUMNOTEQUAL:158,OP_LESSTHAN:159,OP_GREATERTHAN:160,OP_LESSTHANOREQUAL:161,OP_GREATERTHANOREQUAL:162,OP_MIN:163,OP_MAX:164,OP_WITHIN:165,OP_RIPEMD160:166,OP_SHA1:167,OP_SHA256:168,OP_HASH160:169,OP_HASH256:170,OP_CODESEPARATOR:171,OP_CHECKSIG:172,OP_CHECKSIGVERIFY:173,OP_CHECKMULTISIG:174,OP_CHECKMULTISIGVERIFY:175,OP_NOP1:176,OP_NOP2:177,OP_NOP3:178,OP_NOP4:179,OP_NOP5:180,OP_NOP6:181,OP_NOP7:182,OP_NOP8:183,OP_NOP9:184,OP_NOP10:185,OP_PUBKEYHASH:253,OP_PUBKEY:254,OP_INVALIDOPCODE:255};t.reverseMap=[];for(var e in t.map){t.reverseMap[t.map[e]]=e}})();(function(){var Opcode=Bitcoin.Opcode;for(var i in Opcode.map){eval("var "+i+" = "+Opcode.map[i]+";")}var Script=Bitcoin.Script=function(t){if(!t){this.buffer=[]}else if("string"==typeof t){this.buffer=Crypto.util.base64ToBytes(t)}else if(Bitcoin.Util.isArray(t)){this.buffer=t}else if(t instanceof Script){this.buffer=t.buffer}else{throw new Error("Invalid script")}this.parse()};Script.prototype.parse=function(){var t=this;this.chunks=[];var e=0;function i(i){t.chunks.push(t.buffer.slice(e,e+i));e+=i}while(e<this.buffer.length){var r=this.buffer[e++];if(r>=240){r=r<<8|this.buffer[e++]}var n;if(r>0&&r<OP_PUSHDATA1){i(r)}else if(r==OP_PUSHDATA1){n=this.buffer[e++];i(n)}else if(r==OP_PUSHDATA2){n=this.buffer[e++]<<8|this.buffer[e++];i(n)}else if(r==OP_PUSHDATA4){n=this.buffer[e++]<<24|this.buffer[e++]<<16|this.buffer[e++]<<8|this.buffer[e++];i(n)}else{this.chunks.push(r)}}};Script.prototype.getOutType=function(){if(this.chunks[this.chunks.length-1]==OP_CHECKMULTISIG&&this.chunks[this.chunks.length-2]<=3){return"Multisig"}else if(this.chunks.length==5&&this.chunks[0]==OP_DUP&&this.chunks[1]==OP_HASH160&&this.chunks[3]==OP_EQUALVERIFY&&this.chunks[4]==OP_CHECKSIG){return"Address"}else if(this.chunks.length==2&&this.chunks[1]==OP_CHECKSIG){return"Pubkey"}else{return"Strange"}};Script.prototype.simpleOutHash=function(){switch(this.getOutType()){case"Address":return this.chunks[2];case"Pubkey":return Bitcoin.Util.sha256ripe160(this.chunks[0]);default:throw new Error("Encountered non-standard scriptPubKey")}};Script.prototype.simpleOutPubKeyHash=Script.prototype.simpleOutHash;Script.prototype.getInType=function(){if(this.chunks.length==1&&Bitcoin.Util.isArray(this.chunks[0])){return"Pubkey"}else if(this.chunks.length==2&&Bitcoin.Util.isArray(this.chunks[0])&&Bitcoin.Util.isArray(this.chunks[1])){return"Address"}else{return"Strange"}};Script.prototype.simpleInPubKey=function(){switch(this.getInType()){case"Address":return this.chunks[1];case"Pubkey":throw new Error("Script does not contain pubkey.");default:throw new Error("Encountered non-standard scriptSig")}};Script.prototype.simpleInHash=function(){return Bitcoin.Util.sha256ripe160(this.simpleInPubKey())};Script.prototype.simpleInPubKeyHash=Script.prototype.simpleInHash;Script.prototype.writeOp=function(t){this.buffer.push(t);this.chunks.push(t)};Script.prototype.writeBytes=function(t){if(t.length<OP_PUSHDATA1){this.buffer.push(t.length)}else if(t.length<=255){this.buffer.push(OP_PUSHDATA1);this.buffer.push(t.length)}else if(t.length<=65535){this.buffer.push(OP_PUSHDATA2);this.buffer.push(t.length&255);this.buffer.push(t.length>>>8&255)}else{this.buffer.push(OP_PUSHDATA4);this.buffer.push(t.length&255);this.buffer.push(t.length>>>8&255);this.buffer.push(t.length>>>16&255);this.buffer.push(t.length>>>24&255)}this.buffer=this.buffer.concat(t);this.chunks.push(t)};Script.createOutputScript=function(t){var e=new Script;e.writeOp(OP_DUP);e.writeOp(OP_HASH160);e.writeBytes(t.hash);e.writeOp(OP_EQUALVERIFY);e.writeOp(OP_CHECKSIG);return e};Script.prototype.extractAddresses=function(t){switch(this.getOutType()){case"Address":t.push(new Address(this.chunks[2]));return 1;case"Pubkey":t.push(new Address(Util.sha256ripe160(this.chunks[0])));return 1;case"Multisig":for(var e=1;e<this.chunks.length-2;++e){t.push(new Address(Util.sha256ripe160(this.chunks[e])))}return this.chunks[0]-OP_1+1;default:throw new Error("Encountered non-standard scriptPubKey")}};Script.createMultiSigOutputScript=function(t,e){var i=new Bitcoin.Script;i.writeOp(OP_1+t-1);for(var r=0;r<e.length;++r){i.writeBytes(e[r])}i.writeOp(OP_1+e.length-1);i.writeOp(OP_CHECKMULTISIG);return i};Script.createInputScript=function(t,e){var i=new Script;i.writeBytes(t);i.writeBytes(e);return i};Script.prototype.clone=function(){return new Script(this.buffer)}})();(function(){var t=Bitcoin.Script;var e=Bitcoin.Transaction=function(t){this.version=1;this.lock_time=0;this.ins=[];this.outs=[];this.timestamp=null;this.block=null;if(t){if(t.hash)this.hash=t.hash;if(t.version)this.version=t.version;if(t.lock_time)this.lock_time=t.lock_time;if(t.ins&&t.ins.length){for(var e=0;e<t.ins.length;e++){this.addInput(new u(t.ins[e]))}}if(t.outs&&t.outs.length){for(var e=0;e<t.outs.length;e++){this.addOutput(new a(t.outs[e]))}}if(t.timestamp)this.timestamp=t.timestamp;if(t.block)this.block=t.block}};e.objectify=function(t){var i=[];for(var r=0;r<t.length;r++){i.push(new e(t[r]))}return i};e.prototype.addInput=function(t,e){if(arguments[0]instanceof u){this.ins.push(arguments[0])}else{this.ins.push(new u({outpoint:{hash:t.hash,index:e},script:new Bitcoin.Script,sequence:4294967295}))}};e.prototype.addOutput=function(e,i){if(arguments[0]instanceof a){this.outs.push(arguments[0])}else{if(i instanceof BigInteger){i=i.toByteArrayUnsigned().reverse();while(i.length<8)i.push(0)}else if(Bitcoin.Util.isArray(i)){}this.outs.push(new a({value:i,script:t.createOutputScript(e)}))}};e.prototype.serialize=function(){var t=[];t=t.concat(Crypto.util.wordsToBytes([parseInt(this.version)]).reverse());t=t.concat(Bitcoin.Util.numToVarInt(this.ins.length));for(var e=0;e<this.ins.length;e++){var i=this.ins[e];t=t.concat(Crypto.util.base64ToBytes(i.outpoint.hash));t=t.concat(Crypto.util.wordsToBytes([parseInt(i.outpoint.index)]).reverse());var r=i.script.buffer;t=t.concat(Bitcoin.Util.numToVarInt(r.length));t=t.concat(r);t=t.concat(Crypto.util.wordsToBytes([parseInt(i.sequence)]).reverse())}t=t.concat(Bitcoin.Util.numToVarInt(this.outs.length));for(var e=0;e<this.outs.length;e++){var n=this.outs[e];t=t.concat(n.value);var r=n.script.buffer;t=t.concat(Bitcoin.Util.numToVarInt(r.length));t=t.concat(r)}t=t.concat(Crypto.util.wordsToBytes([parseInt(this.lock_time)]).reverse());return t};var i=171;var r=1;var n=2;var s=3;var o=80;e.prototype.hashTransactionForSignature=function(e,i,r){var u=this.clone();for(var a=0;a<u.ins.length;a++){u.ins[a].script=new t}u.ins[i].script=e;if((r&31)==n){u.outs=[];for(var a=0;a<u.ins.length;a++)if(a!=i)u.ins[a].sequence=0}else if((r&31)==s){}if(r&o){u.ins=[u.ins[i]]}var h=u.serialize();h=h.concat(Crypto.util.wordsToBytes([parseInt(r)]).reverse());var p=Crypto.SHA256(h,{asBytes:true});return Crypto.SHA256(p,{asBytes:true})};e.prototype.getHash=function(){var t=this.serialize();return Crypto.SHA256(Crypto.SHA256(t,{asBytes:true}),{asBytes:true})};e.prototype.clone=function(){var t=new e;t.version=this.version;t.lock_time=this.lock_time;for(var i=0;i<this.ins.length;i++){var r=this.ins[i].clone();t.addInput(r)}for(var i=0;i<this.outs.length;i++){var n=this.outs[i].clone();t.addOutput(n)}return t};e.prototype.analyze=function(t){if(!(t instanceof Bitcoin.Wallet))return null;var e=true,i=true,r=null,n=null,s=null;for(var o=this.outs.length-1;o>=0;o--){var u=this.outs[o];var a=u.script.simpleOutPubKeyHash();if(!t.hasHash(a)){i=false}else{n=a}r=a}for(var o=this.ins.length-1;o>=0;o--){var h=this.ins[o];s=h.script.simpleInPubKeyHash();if(!t.hasHash(s)){e=false;break}}var p=this.calcImpact(t);var f={};f.impact=p;if(p.sign>0&&p.value.compareTo(BigInteger.ZERO)>0){f.type="recv";f.addr=new Bitcoin.Address(n)}else if(e&&i){f.type="self"}else if(e){f.type="sent";f.addr=new Bitcoin.Address(r)}else{f.type="other"}return f};e.prototype.getDescription=function(t){var e=this.analyze(t);if(!e)return"";switch(e.type){case"recv":return"Received with "+e.addr;break;case"sent":return"Payment to "+e.addr;break;case"self":return"Payment to yourself";break;case"other":default:return""}};e.prototype.getTotalOutValue=function(){var t=BigInteger.ZERO;for(var e=0;e<this.outs.length;e++){var i=this.outs[e];t=t.add(Bitcoin.Util.valueToBigInt(i.value))}return t};e.prototype.getTotalValue=e.prototype.getTotalOutValue;e.prototype.calcImpact=function(t){if(!(t instanceof Bitcoin.Wallet))return BigInteger.ZERO;var e=BigInteger.ZERO;for(var i=0;i<this.outs.length;i++){var r=this.outs[i];var n=Crypto.util.bytesToBase64(r.script.simpleOutPubKeyHash());if(t.hasHash(n)){e=e.add(Bitcoin.Util.valueToBigInt(r.value))}}var s=BigInteger.ZERO;for(var i=0;i<this.ins.length;i++){var o=this.ins[i];var n=Crypto.util.bytesToBase64(o.script.simpleInPubKeyHash());if(t.hasHash(n)){var u=t.txIndex[o.outpoint.hash];if(u){s=s.add(Bitcoin.Util.valueToBigInt(u.outs[o.outpoint.index].value))}}}if(e.compareTo(s)>=0){return{sign:1,value:e.subtract(s)}}else{return{sign:-1,value:s.subtract(e)}}};var u=Bitcoin.TransactionIn=function(e){this.outpoint=e.outpoint;
if(e.script instanceof t){this.script=e.script}else{this.script=new t(e.script)}this.sequence=e.sequence};u.prototype.clone=function(){var t=new u({outpoint:{hash:this.outpoint.hash,index:this.outpoint.index},script:this.script.clone(),sequence:this.sequence});return t};var a=Bitcoin.TransactionOut=function(e){if(e.script instanceof t){this.script=e.script}else{this.script=new t(e.script)}if(Bitcoin.Util.isArray(e.value)){this.value=e.value}else if("string"==typeof e.value){var i=new BigInteger(e.value,10).toString(16);while(i.length<16)i="0"+i;this.value=Crypto.util.hexToBytes(i)}};a.prototype.clone=function(){var t=new a({script:this.script.clone(),value:this.value.slice(0)});return t}})();Bitcoin.Message=function(){var t={};t.magicPrefix="Bitcoin Signed Message:\n";t.makeMagicMessage=function(e){var i=Crypto.charenc.UTF8.stringToBytes(t.magicPrefix);var r=Crypto.charenc.UTF8.stringToBytes(e);var n=[];n=n.concat(Bitcoin.Util.numToVarInt(i.length));n=n.concat(i);n=n.concat(Bitcoin.Util.numToVarInt(r.length));n=n.concat(r);return n};t.getHash=function(e){var i=t.makeMagicMessage(e);return Crypto.SHA256(Crypto.SHA256(i,{asBytes:true}),{asBytes:true})};t.signMessage=function(e,i,r){var n=t.getHash(i);var s=e.sign(n);var o=Bitcoin.ECDSA.parseSig(s);var u=e.getBitcoinAddress().toString();var a=Bitcoin.ECDSA.calcPubkeyRecoveryParam(u,o.r,o.s,n);a+=27;if(r)a+=4;var h=o.r.toByteArrayUnsigned();var p=o.s.toByteArrayUnsigned();while(h.length<32)h.unshift(0);while(p.length<32)p.unshift(0);s=[a].concat(h).concat(p);return Crypto.util.bytesToBase64(s)};t.verifyMessage=function(e,i,r){i=Crypto.util.base64ToBytes(i);i=Bitcoin.ECDSA.parseSigCompact(i);var n=t.getHash(r);var s=!!(i.i&4);var o=Bitcoin.ECDSA.recoverPubKey(i.r,i.s,n,i.i);o.setCompressed(s);var u=o.getBitcoinAddress().toString();return e===u};return t}();return { Bitcoin: window.Bitcoin, Crypto: window.Crypto } })(null, {})
