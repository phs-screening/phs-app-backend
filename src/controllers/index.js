class IndexController {
    getIndex(req, res) {
        res.send('Welcome to the Express backend!');
    }
}

module.exports = IndexController;