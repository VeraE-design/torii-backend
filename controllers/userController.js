const USER = require("../models/user");
const bcrypt = require("bcryptjs");

const handleRegister = async (req, res) => {
  const { fullName, email, password, phoneNumber, role } = req.body;
  try {
    // check if user already exists (email and phoneNumber)
    const existingUser = await USER.findOne({
      $or: [{ email: email || null }, { phoneNumber: phoneNumber || null }],
    });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "Email or phone number already exists" });
    }
    // protect users password
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);
    // verify process
    // save to db
    const user = await USER.create({
      fullName,
      email,
      password: hashedPassword,
      role: role || "tenant",
      phoneNumber,
    });
    return res
      .status(201)
      .json({ success: true, message: "User Registered successfully", user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message });
  }
};

module.exports = { handleRegister };
