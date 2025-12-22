CREATE TABLE employee_profiles (user_id VARCHAR(32) PRIMARY KEY, name VARCHAR(64), title VARCHAR(64));

CREATE TABLE compensation (user_id VARCHAR(32), monthly_salary INT, annual_bonus INT);