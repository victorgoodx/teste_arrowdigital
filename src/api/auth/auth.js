import { Router } from 'express';
import { User } from '../../data/mongooseModels.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import isAdminMiddleware from '../../middlewares/isAdminMiddleware.js';

const router = Router();

// Route for registering a new user
router.post('/register', isAdminMiddleware, async (req, res) => {
    try {
        const { username, password, lab, clinic, email, permissions } = req.body;

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            password: hashedPassword,
            lab,
            clinic,
            email,
            permissions,
        });

        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Route for authenticating a user and generating a JWT token
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const userId = user._id;
        const permissions = user.permissions;
        const labOrClinicId = user.labOrClinicId;

        const expirationDate = new Date();
        expirationDate.setHours(expirationDate.getHours() + 1);

        const userInformation = {
            userId,
            permissions,
            labOrClinicId,
            expirationDate,
        };

        const token = jwt.sign(userInformation, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token, ...userInformation });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Route for logging out (invalidating the token)
router.post('/logout', (req, res) => {
    res.json({ message: 'Logout successful' });
});

export default router;
