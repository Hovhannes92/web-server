import express, { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import postgres from 'postgres';
import { createClient } from 'redis';
import { request } from 'undici';
import dotenv from 'dotenv';
import { gunzip } from 'zlib';
import { promisify } from 'util';

dotenv.config();

const app = express();
app.use(express.json());

// Database connection
const sql = postgres(process.env.DATABASE_URL || '', { ssl: false });

// Redis client
const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.on('error', (err) => console.error('Redis Client Error', err));

(async () => {
  await redisClient.connect();
})();

const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const encodedData = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
const authorizationHeaderString = `Basic ${encodedData}`;

interface Item {
  market_hash_name: string;
  min_price: number;
  tradable: boolean;
}

interface AuthenticatedRequest extends Request {
  userId: number;
}

app.use((req: Request, res: Response, next: NextFunction) => {
  const userId = req.headers['user-id'];

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  (req as AuthenticatedRequest).userId = parseInt(userId as string, 10);
  next();
});

// Endpoint 1: User Authentication (Login)
app.post('/auth', async (req, res) => {
  const { username, password } = req.body as { username: string; password: string };

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const [user] = await sql`
      SELECT * FROM users WHERE username = ${username}
    `;

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    return res.json({ userId: user.id, message: 'Authenticated successfully' });
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint 2: Change Password
app.put('/change-password', async (req, res) => {
  const { oldPassword, newPassword } = req.body as { oldPassword: string; newPassword: string };
  const userId = (req as AuthenticatedRequest).userId;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Old password and new password are required' });
  }

  try {
    const [user] = await sql`
      SELECT * FROM users WHERE id = ${userId}
    `;

    if (!user || !(await bcrypt.compare(oldPassword, user.password))) {
      return res.status(401).json({ error: 'Incorrect old password' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await sql`
      UPDATE users SET password = ${hashedPassword} WHERE id = ${userId}
    `;

    return res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Password change error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint 3: Display Items with Minimal Prices (Caching with Redis)
app.get('/items', async (req, res) => {
  const cacheKey = 'items:min_prices';

  // Promisified gunzip function for decompression
const gunzipAsync = promisify(gunzip);

  try {
    const cachedItems = await redisClient.get(cacheKey);
    if (cachedItems) {
      return res.json(JSON.parse(cachedItems));
    }

    const apiUrl = 'https://api.skinport.com/v1/items?app_id=730&currency=EUR&tradable=0';
    const response = await request(apiUrl, {
      method: 'GET',
      headers: {
        'Accept-Encoding': 'gzip',
        'Authorization': authorizationHeaderString,
      },
    });

    if (response.statusCode !== 200) {
      return res.status(response.statusCode).json({ error: 'Failed to fetch items from API' });
    }

    // Get the response body as a Buffer and decompress if gzipped
    const compressedBody = await response.body.arrayBuffer();
    const decompressedBody = await gunzipAsync(Buffer.from(compressedBody));

    // Parse the decompressed response as JSON
    const items = JSON.parse(decompressedBody.toString()) as Item[];

    const processedItems = items.map((item) => ({
      name: item.market_hash_name,
      min_price: item.min_price,
      tradable: item.tradable
    }));

    await redisClient.set(cacheKey, JSON.stringify(processedItems), { EX: 3600 });
    return res.json(processedItems);
  } catch (error) {
    console.error('Error fetching items:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint 4: Purchase Item
app.post('/purchase', async (req, res) => {
  const userId = (req as AuthenticatedRequest).userId;
  const { itemId } = req.body as { itemId: number };

  if (!itemId) {
    return res.status(400).json({ error: 'Item ID is required' });
  }

  try {
    const [user] = await sql`SELECT * FROM users WHERE id = ${userId}`;
    const [item] = await sql`SELECT * FROM items WHERE id = ${itemId}`;

    if (!item) {
      return res.status(404).json({ error: 'Item not found' });
    }

    const itemPrice = item.tradable_price || item.non_tradable_price;

    if (user.balance < itemPrice) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    await sql.begin(async (sql) => {
      await sql`
        UPDATE users SET balance = balance - ${itemPrice} WHERE id = ${userId}
      `;
      await sql`
        INSERT INTO purchases (user_id, item_id, purchase_price)
        VALUES (${userId}, ${itemId}, ${itemPrice})
      `;
    });

    const [updatedUser] = await sql`SELECT balance FROM users WHERE id = ${userId}`;
    return res.json({ message: 'Purchase successful', balance: updatedUser.balance });
  } catch (error) {
    console.error('Purchase error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
