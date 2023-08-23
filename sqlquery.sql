CREATE DATABASE blog_db_final;
USE blog_db_final;

-- Drop existing tables (if they exist)
DROP TABLE IF EXISTS blogs;
DROP TABLE IF EXISTS users;

-- Create 'users' table
CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    fullname VARCHAR(255) NOT NULL
);

-- Create 'blogs' table
CREATE TABLE IF NOT EXISTS blogs (
    blog_id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
