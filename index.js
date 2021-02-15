const Crypto = require('crypto-js')

// Convert a hex string to a byte array
function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}
function longToHex(long){
    return Number(long).toString(16).toUpperCase();
}
function truncatedvalue(h, p) {
    // h is the hash value
    // p is precision
    let offset = h[h.length-1] & 0xf;

    let v = ((h[offset] & 0x7f) << 24) |
        ((h[offset + 1] & 0xff) << 16) |
        ((h[offset + 2] & 0xff) << 8) |
        ((h[offset + 3] & 0xff))
    v = "" + v;
    v = v.substr(v.length - p, p);
    return v;
}
function getPeriod(X = 30,T0=0){
    return Math.floor(((new Date).getTime()-T0) / 1000 / X)
}

module.exports.Generate = (key, length, period=30, T0=0) => {
    let time = longToHex(getPeriod(period,T0))
    while(time.length < 16) time = `0${time}`
    const hmacBytes = Crypto.HmacSHA1(time,key)
    return truncatedvalue(hexToBytes(hmacBytes.toString()), length);
}

module.exports.Validate = (token, key, length, period=30, T0=0) => {
    let periods = [getPeriod(period,T0)]
    periods.push(periods[0]-1)
    periods.push(periods[0]-2)

    let time = (x) => {
        let result = longToHex(x)
        while(result.length < 16) result = `0${result}`
        return result
    }
    const hmacBytes = periods.map(i => {
        return time(i)
    }).map(i => {
        return Crypto.HmacSHA1(i, key)
    })
    return hmacBytes.map(i => truncatedvalue(hexToBytes(i.toString()), length)).filter(i => i===token).length > 0;
}