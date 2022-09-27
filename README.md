# Node.js & Passport Login

This is a user login and registration app using Node.js, Express, Passport, Mongoose, EJS and some other packages.

### Version: 2.0.0

### Usage

```sh
$ npm install
```

```sh
$ npm start
# Or run with Nodemon
$ npm run dev

# Visit http://localhost:5000
```

### MongoDB

Open "config/keys.js" and add your MongoDB URI, local or Atlas

Example for local configuration in `config/keys.js` if you run mongodb in docker container. Get IP-Address of container via `docker inspect`.
```
module.exports = {
    mongoURI: "mongodb://172.17.0.2:27017/local"
};
```
