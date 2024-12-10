'use strict';
const {
  Model
} = require('sequelize');
const bcrypt = require('bcryptjs');
module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
    }
  }
  User.init({
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: {
        msg: 'Username exists already'
      },
      validate: {
        notEmpty: {
          msg: 'Username cannot be empty'
        },
        len: {
          args: [6, 255],
          msg: 'Username must be at least 6 characters',
        }
      }
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: {
          msg: 'Password cannot be empty'
        },
        len: {
          args: [8, 255],
          msg: 'Password must be at least 8 characters',
        }
      }
    },
  }, {
    sequelize,
    modelName: 'User',
    hooks: {
      beforeSave: async (user) => {
        if (user.isNewRecord || user.changed('password')) {
          if (user.password) {
            user.password = await bcrypt.hash(user.password, 10);
          }
        }
      }
    }
  });
  return User;
};