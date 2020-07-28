/**
 * Gun adapter to perform transparent
 *  - encryption/decryption
 *  - signing/verifying
 *  - consider DNS (denial of service) attacks!
 *
 * This adapter is for browser peers and is much more restrictive to mitigate
 * spam attacks.
 *
 * @author: Bernhard Lukassen
 */


class GunAdapter {

    constructor() {
        this.plugins = [];
    }

    use(plugin) {
        this.plugins.push(plugin);
    }

    /*
     * gun adapter implementation
     */

    engage() {
        // Engage this GUN adapter, we first listen to when a gun instance is created (and when its options change)
        universe.Gun.on('opt', function(at){
            if(!at.everblack){ // only add once per instance, on the "at" context.
                at.everblack = everblack;
                everblack.at = at;
                at.on('in', everblack.in, at);
                at.on('out', everblack.out, at);
                at.on('node', everblack.node, at);
                at.on('put', everblack.put, at);
                at.on('get', everblack.get, at);
            }
            this.to.next(at); // make sure to call the "next" middleware adapter.
        });
    }
}

const adapter = new GunAdapter();

const everblack = {
    node(request) {
        this.to.next(request);
    },

    // check for DNS (denial of service) attacks
    in(request) {
        this.to.next(request);
    },

    // not utilized, needs no processing
    out(request) {
        this.to.next(request);
    },

    // encrypt
    put(request) {
        this.to.next(request);
    },

    // decrypt
    get(request) {
        this.to.next(request);
    },

};

export default adapter;
