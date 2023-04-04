-- migrate:up
CREATE TABLE cart (
id INT NOT NULL AUTO_INCREMENT,
user_id INT NOT NULL,
items JSON,
PRIMARY KEY(id),
CONSTRAINT userId_FK FOREIGN KEY (user_id) REFERENCES users(id)
)
-- migrate:down

