-- Create opt_out table
CREATE TABLE opt_out (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    school VARCHAR(255) NOT NULL,
    opt_out BOOLEAN NOT NULL DEFAULT false
);