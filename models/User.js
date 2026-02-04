const bcrypt = require('bcrypt');

const users = [];

class User {
  async findByEmail(email) {
    return users.find(user => user.email === email) || null;
  }

  async create(userData) {
    const { email, password, name } = userData;

    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
      throw new Error('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: users.length + 1,
      email,
      password: hashedPassword,
      name,
      createdAt: new Date()
    };

    users.push(user);
    return { id: user.id, email: user.email, name: user.name };
  }

  async validatePassword(email, password) {
    const user = users.find(user => user.email === email);
    if (!user) {
      return false;
    }

    return await bcrypt.compare(password, user.password);
  }
}

module.exports = new User();
