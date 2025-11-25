const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Op } = require("sequelize");
const userAgent = require("express-useragent");

// --- UTILITY/HELPER IMPORTS ---
const { generateOtp, sendOtp } = require("../controller/otpController");

// --- MODEL IMPORTS ---
const User = require("../model/userModel");
const OTP = require("../model/otpModel");
const RoleType = require("../model/roletypeMaster");
const Hospital = require("../model/hospitalMaster");
const Nodal = require("../model/nodalMaster");
const Doctor = require("../model/doctorRegistration");
const Session = require("../model/userSessions");

/**
 * @description Checks if a user exists and creates a default admin user and role if the database is empty.
 * @returns {Promise<void>}
 */
const checkAdmin = async () => {
  try {
    const userCount = await User.count();
    if (userCount === 0) {
      // 1. Ensure Admin Role Exists
      let adminRole = await RoleType.findOne({ where: { roletype: "admin" } });
      if (!adminRole) {
        adminRole = await RoleType.create({
          roletype: "admin",
          isactive: true,
          roledescription: "Administrator with full access",
        });
        console.log("Admin role created in RoleType table");
      }

      // 2. Create Default Admin User
      const hashedPassword = await bcrypt.hash("Admin@123", 10);
      await User.create({
        email: "admin@example.com",
        first_name: "Asr",
        last_name: "Admin",
        mobile_number: "0000000000",
        alternate_number: "0000000000",
        wattsapp_number: "0000000000",
        gender: "Male",
        dob: "1990-01-01",
        address: "Admin Address",
        city: "Admin City",
        state: "Admin State",
        pincode: "000000",
        module: ["admin"],
        created_by: 0,
        username: "Admin",
        password: hashedPassword,
        role: adminRole.id,
      });

      console.log("Default admin user created: Admin / Admin@123");
    }
  } catch (error) {
    console.error(`Error checking admin user: ${error.message}`);
  }
};

/**
 * @description Registers a new user with password hashing.
 * @route POST /lims/api/auth/signup
 */
const createUser = async (req, res) => {
  try {
    const {
      wattsapp_number,
      mobile_number,
      alternate_number,
      email,
      first_name,
      last_name,
      gender,
      dob,
      address,
      city,
      state,
      pincode,
      username,
      password,
      created_by,
      image,
      module,
      certificate,
      nominee_contact,
      nominee_name,
    } = req.body;

    // Check for existing user based on unique constraints
    const existingUser = await User.findOne({
      where: {
        [Op.or]: [{ username }, { first_name }, { mobile_number }],
      },
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Username, Mobile, or Name combination already exists.",
        error: "DUPLICATE_USER_ATTRIBUTES",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      wattsapp_number,
      mobile_number,
      alternate_number,
      email,
      first_name,
      last_name,
      gender,
      dob,
      address,
      city,
      state,
      pincode,
      username,
      password: hashedPassword,
      created_by,
      image,
      module,
      certificate,
      nominee_contact,
      nominee_name,
    });

    return res.status(201).json({
      message: "User Created Successfully (Role not assigned yet)",
    });
  } catch (err) {
    console.error("User Creation Failed:", err.message);
    return res
      .status(400)
      .json({ message: `User Creation Failed: ${err.message}` });
  }
};

/**
 * @description Assigns a specific role (and related association IDs) to an existing user with validation.
 * @route POST /lims/api/users/assign-role
 */
const assignRole = async (req, res) => {
  try {
    const { user_id, role, module, hospitalid, nodalid, doctor_id } = req.body;

    let targetUserId = user_id;
    let targetRoleId = role;

    // 1. If doctor_id is provided, ensure a user exists for that doctor
    if (doctor_id) {
      let doctorUser = await User.findOne({ where: { doctor_id } });
      const doctor = await Doctor.findByPk(doctor_id);

      if (!doctor) {
        return res.status(404).json({ message: "Doctor not found" });
      }

      const hashedPassword = await bcrypt.hash(doctor.ddob.toString(), 10);

      if (!doctorUser) {
        const doctorRole = await RoleType.findOne({
          where: { roletype: "doctor" },
        });
        if (!doctorRole) {
          return res
            .status(404)
            .json({ message: "Doctor role type not found" });
        }

        doctorUser = await User.create({
          doctor_id,
          role: doctorRole.id,
          // module: [doctor.assign_ddpt],
          module: [doctor.assign_ddpt, doctor.ddpt],
          hospitalid,
          nodalid,
          created_by: "admin",
          wattsapp_number: doctor.dwhtsap,
          mobile_number: doctor.dcnt,
          email: doctor.demail,
          first_name: doctor.dname,
          gender: "Other",
          dob: doctor.ddob,
          username: doctor.demail,
          password: hashedPassword,
          image: doctor.dphoto,
          doc_sig: doctor.dditsig,
        });
      }

      // ✅ Always set targetUserId from doctorUser
      targetUserId = doctorUser.user_id;
      targetRoleId = doctorUser.role;
      console.log(`Doctor user created/used with ID: ${targetUserId}`);
    }

    // 2. Fetch the user (either original or doctor-created)
    const user = await User.findByPk(targetUserId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 3. Validate Role Existence
    const roleRecord = await RoleType.findByPk(targetRoleId);
    if (!roleRecord) {
      return res.status(404).json({ message: "Invalid Role ID" });
    }

    const roleName = roleRecord.roletype.toLowerCase();

    // 4. Conditional Hospital/Association Validation
    const requiresHospitalOrNodal = ![
      "admin",
      "reception",
      "technician",
      "doctor",
      "hr",
    ].includes(roleName);

    if (requiresHospitalOrNodal && !hospitalid) {
      return res
        .status(400)
        .json({ message: "Hospital ID is required for this role" });
    }

    if (hospitalid && !(await Hospital.findByPk(hospitalid))) {
      return res.status(400).json({ message: "Invalid Hospital ID provided." });
    }

    if (nodalid && !(await Nodal.findByPk(nodalid))) {
      return res.status(400).json({ message: "Invalid Nodal ID provided." });
    }

    // 5. Update user associations based on role
    await user.update({
      role,
      module,
      hospitalid: roleName === "admin" ? null : hospitalid,
      nodalid: roleName === "admin" ? null : nodalid,
      doctor_id: roleName === "doctor" ? doctor_id : null,
      update_by: "admin",
      update_date: new Date(),
    });

    return res.status(200).json({
      message: "Role and associations assigned successfully",
    });
  } catch (err) {
    // Log full error object for debugging
  console.error("Role Assignment Failed:", err);

  // Optionally log specific fields if using Sequelize
  if (err.errors) {
    err.errors.forEach(e => console.error(`Field: ${e.path}, Message: ${e.message}`));
  }

  // Return detailed error info in response (safe subset)
  return res.status(500).json({
    message: "Role Assignment Failed",
    error: {
      name: err.name,
      message: err.message,
      details: err.errors || null
    }
  });

  }
};

/**
 * @description Handles user login, performing password validation and complex role-based authentication flow (including OTP for Admin).
 * @route POST /lims/api/auth/login
 */
const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. Find user and include associated models
    const user = await User.findOne({
      where: { username },
      include: [
        { model: Hospital, attributes: ["id", "hospitalname"] },
        { model: Nodal, attributes: ["id", "nodalname"] },
        { model: Doctor, attributes: ["dname", "dditsig", "dphoto"] },
        { model: RoleType, as: "roleType", attributes: ["roletype"] },
      ],
    });

    if (!user) {
      return res
        .status(404)
        .json({ message: "No User found with this username." });
    }

    // 2. Compare the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "Invalid credentials (Password mismatch)." });
    }

    // Get role type string
    const roleType = user.roleType
      ? user.roleType.roletype.toLowerCase()
      : "unknown";
    if (roleType === "unknown") {
      return res
        .status(500)
        .json({ message: "User role type could not be determined." });
    }

    // 3. Handle Admin Users (OTP Flow)
    if (roleType === "admin") {
      const otp = generateOtp();
      // Delete any old OTP and create a new one
      await OTP.destroy({ where: { user_id: user.user_id } });
      await OTP.create({
        user_id: user.user_id,
        otp,
        expires_at: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes expiry
      });
      // await sendOtp(process.env.PREDEFINED_EMAIL, otp); // Assuming this is defined

      return res.status(200).json({
        message: "Admin detected. OTP sent for verification.",
        id: user.user_id,
        role: user.role,
        roleType: roleType,
        // WARNING: Returning OTP in response is a security risk. Should only be returned here for testing.
        otp: otp,
      });
    }

    // 4. Handle Role-Specific Access Checks & Token Generation
    const tokenPayload = {
      userid: user.user_id,
      role: user.role,
      roleType: roleType,
      hospitalid: user.hospitalid,
      nodalid: user.nodalid,
      hospitalname: user.hospital?.hospitalname || null,
      nodalname: user.nodal?.nodalname || null,
      username: user.username,
      module: user.module,
      digitsignature: user.certificate || null,
    };
    const responseData = {
      success: true,
    };

    switch (roleType) {
      case "phlebotomist":
        if (!user.hospitalid && !user.nodalid) {
          return res.status(403).json({
            message:
              "Access denied: Phlebotomist must be assigned a hospital or nodal.",
          });
        }
        break;

      case "reception":
      case "technician":
        if (!user.nodalid) {
          return res.status(403).json({
            message: `Access denied: ${roleType} must be assigned a nodal.`,
          });
        }
        tokenPayload.nodalid = user.nodalid;
        responseData.nodalname = user.Nodal?.nodalname || "Unknown Nodal";
        // Assuming technician has module information
        if (roleType === "technician") {
          tokenPayload.module = user.module;
          responseData.module = user.module;
        }
        break;

      case "doctor":
        // Doctor association is often optional, check if linked Doctor data is available
        tokenPayload;
        // responseData.module = user.module;
        // responseData.doctor = {
        //   name: user.Doctor?.dname || null,
        //   signature: user.Doctor?.dditsig || null,
        //   profileImage: user.Doctor?.dphoto || null,
        // };
        break;

      default:
        // Other roles (e.g., HR, default user) without specific checks
        break;
    }

    // 5. Session Tracking (Non-Admin Users only)
    await Session.create({
      user_id: user.user_id,
      ip_address: req.ip, // Express built-in IP detection
      user_agent_info: req.headers["user-agent"], // NEW: Capture User-Agent
    });

    // 5. Generate and return the JWT token
    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
      // expiresIn: '1h'
    });

    return res.status(200).json({
      ...responseData,
      token,
    });
  } catch (e) {
    console.error("Login attempt failed:", e);
    return res.status(500).json({
      success: false,
      message: "An unexpected error occurred during login.",
      error: e.message,
    });
  }
};

/**
 * @description Verifies the OTP provided by the user (typically for Admin login).
 * @route POST /lims/api/auth/verify-otp
 */
const verifyOtp = async (req, res) => {
  try {
    const { userid, otp } = req.body;

    const user = await User.findByPk(userid);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Find and validate the OTP
    const storedOtp = await OTP.findOne({
      where: { user_id: userid, otp, expiresAt: { [Op.gt]: new Date() } },
    });

    if (!storedOtp) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // OTP is valid; delete it after successful verification
    await OTP.destroy({ where: { id: storedOtp.id } });

    await Session.create({
      user_id: user.user_id,
      ip_address: req.ip, // Express built-in IP detection
      user_agent_info: req.headers["user-agent"], // NEW: Capture User-Agent
    });

    // Generate the JWT token
    const roleType = await RoleType.findByPk(user.role);
    const token = jwt.sign(
      {
        userid: user.user_id,
        role: user.role,
        roleType: roleType ? roleType.roletype.toLowerCase() : "unknown",
      },
      process.env.JWT_SECRET
    );

    return res
      .status(200)
      .json({ message: "OTP verified, login successful", token });
  } catch (e) {
    console.error("OTP Verification Failed:", e.message);
    return res.status(500).json({ message: "OTP Verification Failed" });
  }
};

/**
 * @description Generates and resends a new OTP to the specified admin user.
 * @route POST /lims/api/auth/resend-otp/:userId
 */
const resendOtp = async (req, res) => {
  try {
    const { userId } = req.params; // Using userId (camelCase) for consistency with route definition

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate a new OTP
    const otp = generateOtp();

    // Update OTP in the database (delete old, create new)
    await OTP.destroy({ where: { user_id: userId } });
    await OTP.create({ user_id: userId, otp });

    // await sendOtp(process.env.PREDEFINED_EMAIL, otp); // Assuming email is the target

    return res.status(200).json({ message: "OTP resent successfully" });
  } catch (e) {
    console.error("Failed to resend OTP:", e.message);
    return res.status(500).json({ message: "Failed to resend OTP" });
  }
};


/**
 * @description Handle user logout by invalidating the session.record the logut time.
 * @route POST /lims/api/auth/logout
 */

const logout = async (req, res) => {
  try {
    const { userid } = req.user; // Assuming user ID is available in req.user from auth middleware  
    // Find the active session for the user
    const session = await Session.findOne({
      where: { user_id: userid, logout_time: null },
      order: [['login_time', 'DESC']] // Get the most recent active session
    });
    if (!session) {
      return res.status(404).json({ message: "Active session not found" });
    }
    // Update the session to set logout time
    session.logout_time = new Date();
    await session.save();
    return res.status(200).json({ message: "Logout successful" });
  }
  catch (e) {
    console.error("Logout Failed:", e.message);
    return res.status(500).json({ message: "Logout Failed" });
  }
};

/**
 * @description Retrieves a paginated list of all users.
 * @route GET /lims/api/users
 */
const getAllUsers = async (req, res) => {
  try {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const { count, rows } = await User.findAndCountAll({
      limit: limit,
      offset: offset,
      order: [["user_id", "ASC"]],
    });

    const totalPages = Math.ceil(count / limit);

    return res.status(200).json({
      data: rows,
      meta: {
        totalItems: count,
        itemsPerPage: limit,
        currentPage: page,
        totalPages: totalPages,
      },
    });
  } catch (e) {
    console.error("Error retrieving all users:", e.message);
    return res
      .status(500)
      .send({ message: `Something went wrong: ${e.message}` });
  }
};

/**
 * @description Retrieves a single user by their ID.
 * @route GET /lims/api/users/:id
 */
const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json(user);
  } catch (e) {
    return res
      .status(500)
      .json({ message: `Failed to retrieve user: ${e.message}` });
  }
};

/**
 * @description Searches users by username or first name using case-insensitive LIKE.
 * @route GET /lims/api/users/search?username=...&first_name=...
 */
const searchUsers = async (req, res) => {
  try {
    const { username, first_name } = req.query;
    const filters = {};

    if (username) {
      filters["username"] = {
        [Op.iLike]: `%${username}%`,
      };
    }
    if (first_name) {
      filters["first_name"] = {
        [Op.iLike]: `%${first_name}%`,
      };
    }

    // Require at least one filter for a meaningful search
    if (Object.keys(filters).length === 0) {
      return res.status(400).json({
        message: "Must provide a search parameter (username or first_name).",
      });
    }

    const users = await User.findAll({
      where: filters,
      order: [["user_id", "ASC"]],
    });

    return res.status(200).json(users);
  } catch (error) {
    console.error("Error searching users:", error.message);
    return res.status(500).json({
      message: `Something went wrong while searching users: ${error.message}`,
    });
  }
};

/**
 * @description Updates general user profile fields.
 * @route PUT /lims/api/users/:id
 */
const updateUsers = async (req, res) => {
  try {
    const { id } = req.params;
    const {
      first_name,
      last_name,
      mobile_number,
      wattsapp_number,
      alternate_number,
      email,
      dob,
      gender,
      address,
      city,
      state,
      pincode,
      username,
      password,
      module,
      isactive,
    } = req.body;

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const updateData = {
      first_name,
      last_name,
      mobile_number,
      wattsapp_number,
      alternate_number,
      email,
      dob,
      gender,
      address,
      city,
      state,
      pincode,
      username,
      module,
      isactive,
    };

    // Hash password if it is provided
    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }

    await user.update(updateData);

    return res.status(200).json({ message: "User updated successfully", user });
  } catch (e) {
    console.error("Error updating user:", e.message);
    return res
      .status(500)
      .json({ message: "Failed to update user", error: e.message });
  }
};

/**
 * @description Updates only the user's role and associated linkage IDs (hospital/nodal/doctor).
 * NOTE: This is a simpler update than `assignRole` which includes complex role validation.
 * @route PUT /lims/api/users/:id/role-associations
 */
const updateUserAssociations = async (req, res) => {
  try {
    const { id } = req.params;
    const { role, module, hospitalid, nodalid } = req.body;

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const updateFields = { role, module, hospitalid, nodalid };

    await user.update(updateFields);

    return res
      .status(200)
      .json({ message: "User role and association updated successfully" });
  } catch (error) {
    console.error("Failed to update user associations:", error.message);
    return res.status(500).json({
      message: "Failed to update user associations",
      err: error.message,
    });
  }
};

module.exports = {
  login,
  verifyOtp,
  resendOtp,
  createUser,
  assignRole,
  checkAdmin,
  getAllUsers,
  searchUsers,
  getUserById,
  updateUsers,
  updateUserAssociations,
  logout,
};
