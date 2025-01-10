# Plans for this discord bot management project


* Use node.js backend
* Need the ability to login. 
* One backend can have multiple bots
* The bots will be in a _tab_ or something similar
* Control bots:
	* Restart bot
	* Update bot
	* Change config
	* Backup data/ dir (gzip, then download)
	* Restore data/ dir (upload gzipped archive)
	* Check if the server can be put down for maintenance (check if there are timers in the near future (hour))
	* Add a new bot
	* Download logs (specify time range & file format (gzip or plain))
	* Ability to see a log equivalent to `journalctl -fu discord_bot.service`
	* Statistics (uptime, amount of commands, last error, commands per hour, commands last 24 hours etc..., )

Bots will have an internal api that they communicate with the backend server over.  
Using websockets for the follow log is probably best?

### Misc Thoughts

* Check if there are any software updates? If there are, send email?

First priority: 
* Create a basic html page.

### SQLITE SCHEMAS

TODO: Figure out how to implement permissions and stuff in a good way
```sql
CREATE TABLE users (
	user_id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE,
	hashed_password TEXT,
	email TEXT,
	created_at INTEGER,
	is_verified INTEGER,
	is_administrator INTEGER
);

CREATE TABLE tokens (
	token PRIMARY KEY UNIQUE,
	user_id INTEGER,
	expires_at INTEGER
);

CREATE TABLE discord_bots ( 
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	owner_id INTEGER,
	is_public INTEGER,

);

```