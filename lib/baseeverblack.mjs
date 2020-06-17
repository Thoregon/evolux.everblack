/**
 *
 *
 * @author: Bernhard Lukassen
 */

const rnd = universe.Gun.text.random;
const SEA = universe.Gun.SEA;

const BaseEverblack = base => class extends base {

    /*
     * utils
     */

    random(len) {
        return rnd(len);
    }

    get salt() {
        return rnd(16);
    }

    async work(data, salt) {
        return await SEA.work(data, salt);
    }

    async pair() {
        return await SEA.pair();
    }

}

export default BaseEverblack;
