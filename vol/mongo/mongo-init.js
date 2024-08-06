db = db.getSiblingDB('admin');
// log as root admin if you decided to authenticate in your docker compose file
db.auth("root", "root");
// create db
db = db.getSiblingDB('user_db')
// create user
db.createUser({
    'user': "user",
    'pwd': "password",
    'roles': [{
        'role': 'dbOwner',
        'db': 'user_db'
    }]
});

// first collection required for mongo init
db.createCollection('init');