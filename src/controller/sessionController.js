const { Op } = require("sequelize");
const Session = require("../model/userSessions");
const User = require("../model/userModel");
const Role = require("../model/roletypeMaster");

/**
 * @description Retrieves a paginated list of all user session logs for administrative review.
 * @route GET /lims/api/sessions/all-logs
 * @requires Admin role authorization middleware.
 */
const getAllSessionLogs = async (req, res) => {
    try {
        // Pagination setup
        const page = Number(req.query.page) || 1;
        const limit = Number(req.query.limit) || 20;
        const offset = (page - 1) * limit;

        // Fetch session logs with user details and role info
        const { count, rows } = await Session.findAndCountAll({
            limit: limit,
            offset: offset,
            order: [["login_time", "DESC"]], 
            include: [
                {
                    model: User,
                    as:"users",
                    attributes: ['user_id', 'username', 'first_name', 'last_name', 'email'],
                    include: [{
                        model: Role,
                        as: 'roleType',
                        attributes: ['roletype']
                    }]
                }
            ],
            // Only show sessions that have a login time (which should be all of them)
            where: {
                login_time: { [Op.not]: null }
            }
        });

        const logs = rows.map(session => ({
            sessionId: session.session_id,
            loginTime: session.login_time,
            logoutTime: session.logout_time,
            duration: session.logout_time ? (session.logout_time.getTime() - session.login_time.getTime()) / 1000 : null, // Duration in seconds
            ipAddress: session.ip_address,
            userAgent: session.user_agent_info,
            user: {
                userId: session.users.user_id,
                username: session.users.username,
                fullName: `${session.users.first_name} ${session.users.last_name}`,
                role: session.users.roleType ? session.users.roleType.roletype : 'N/A'
            }
        }));

        return res.status(200).json({
            data: logs,
            meta: {
                totalItems: count,
                itemsPerPage: limit,
                currentPage: page,
                totalPages: Math.ceil(count / limit),
            },
        });

    } catch (e) {
        console.error("Error retrieving all session logs:", e.message);
        return res.status(500).send({ message: "Failed to retrieve session logs.", error: e.message });
    }
};

/**
 * @description Retrieves the session log details for the currently authenticated user.
 * @route GET /lims/api/sessions/my-logs
 * @requires Authentication middleware to set req.user.userid
 */
const getMySessionLogs = async (req, res) => {
    // This assumes authentication middleware has set req.user.userid
    const userId = req.user?.userid; 

    try {
        if (!userId) {
            return res.status(401).json({ message: "User ID not found in token. Authentication required." });
        }

        const logs = await Session.findAll({
            where: {
                user_id: userId
            },
            order: [["login_time", "DESC"]], // Show newest sessions first
            attributes: ['session_id', 'login_time', 'logout_time', 'ip_address', 'user_agent_info']
        });

        const formattedLogs = logs.map(session => ({
            sessionId: session.session_id,
            loginTime: session.login_time,
            logoutTime: session.logout_time,
            duration: session.logout_time ? (session.logout_time.getTime() - session.login_time.getTime()) / 1000 : null, // Duration in seconds
            ipAddress: session.ip_address,
            userAgent: session.user_agent_info,
            status: session.logout_time ? 'Closed' : 'Active'
        }));

        return res.status(200).json({
            message: `Found ${formattedLogs.length} sessions for user ${userId}.`,
            data: formattedLogs,
        });

    } catch (e) {
        console.error("Error retrieving user session logs:", e.message);
        return res.status(500).send({ message: "Failed to retrieve your session logs.", error: e.message });
    }
};


module.exports = {
    getAllSessionLogs,
    getMySessionLogs,
};