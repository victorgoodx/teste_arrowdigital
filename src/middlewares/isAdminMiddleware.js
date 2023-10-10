export default function isAdminMiddleware(req, res, next) {
    const permissions = req.user.permissions;

    if (permissions.includes('admin')) {
        next();
    } else {
        res.status(403).json({ message: 'Unauthorized access' });
    }
}
