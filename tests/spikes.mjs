/**
 *
 *
 * @author: Bernhard Lukassen
 */


import letThereBeLight      from '/evolux.universe';
import { timeout, doAsync } from '/evolux.universe';
import BlackObject          from "../lib/blackobject.mjs";

const init = async () => {
    const everblack = universe.Everblack;

    universe.logger.info('got everblack');

    // create owner role
    let ownerpair = everblack.pair();
    let blackowner = new BlackObject().forOwner(ownerpair);
    // blackobject.

    let permission = {
        pub: { pub: ownerpair.pub, epub: ownerpair.epub },
        roles: [
            'reader'
        ]
    };


    // create reader role
    let readerpair = everblack.pair();

}

const work = async () => {

}

const room = async () => {

}

(async () => {
    try {
        const universe  = await letThereBeLight();

        await init();
        await work();

        // await room();
    } catch (err) {
        console.log(err);
    }
})();
