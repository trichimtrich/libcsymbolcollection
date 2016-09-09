# LibC Symbol Collection
## Whoami
A little Hope in dark day

## Installation
### CLI
```pip install pyelftools```

### WebUI on your-own-server
- Python Flask/Mongo Client ```pip install Flask pymongo```
- Install [MongoDB] (https://www.mongodb.com/) Server as well
- Extract and restore database
```
cd web
unzip dumps.zip
mongorestore -d libc
mongod --dbpath=<whatever folder you want> &
```

- Or just use my sample
```
cd web
unzip libc_mongo.zip
mongod --dbpath=libc_mongo &
```

## Usage
### WebUI
Run `python web.py` or try mine [http://libc.trich.im] (http://libc.trich.im)

### CLI
You are welcome! ```python libc.py help```

## License
Feel free to do whatever you want
