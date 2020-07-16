/**
 *
 *
 * @author: Bernhard Lukassen
 */


import letThereBeLight          from '/evolux.universe';
import { timeout, doAsync }     from '/evolux.universe';

(async () => {
    try {
        const universe = await letThereBeLight();

        const eb = universe.Everblack;

        universe.logger.info('got everblack');
    } catch (err) {
        console.log(err);
    }
})();
