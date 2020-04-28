/**
 * Gun adapter to perform transparent
 *  - encryption/decryption
 *  - signing/verifying
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

    engage(gun) {
        // Engage this GUN adapter, we first listen to when a gun instance is created (and when its options change)
        Gun.on('opt', function(at){
            if(!at.everblack){ // only add once per instance, on the "at" context.
                at.sea = {own: {}};
                at.on('in', everblack.in, at); // now listen to all input data, acting as a firewall.
                at.on('out', everblack.out, at); // and output listeners, to encrypt outgoing data.
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

    in(request) {
        this.to.next(request);
    },

    out(request) {
        this.to.next(request);
    },

    put(request) {
        this.to.next(request);
    },

    get(request) {
        this.to.next(request);
    },

};

export default adapter;
