# LibC Symbol Collection
## Whoami
A little Hope in dark day

## Installation
### CLI
```pip install pyelftools```

### WebUI on your-own-server
- Python Flask/Mongo Client ```pip install Flask pymongo```
- Install [MongoDB] (https://www.mongodb.com/) Server as well
```
mongod --dbpath=<whatever folder you want> &
```

- Restore database
```
cd web
python import_symbol_to_mongo.py ../libc.sym
```

- Or just extract current db directory
```
cd web
unzip libc_db.zip
```

## Usage
### WebUI
Run `python web.py` or try mine [http://libc.trich.im] (http://libc.trich.im)

### CLI
You are welcome! ```python libc.py help```

### Update new lib
- Run scape script to find new lib, export to text file
```
bash scrape_ubuntu_launchpad.sh > new_grab.txt
```

- Download deb and parse, it will create backup and new symbol files
```
python extract_deb.py new_grab.txt <old_grab_file>
```

- Restore to mongo database if needed
```
python web/import_symbol_to_mongo.py ../libc.sym
```

## License
Feel free to do whatever you want
