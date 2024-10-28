import postgres from 'postgres';
import { request } from 'undici';
import dotenv from 'dotenv';
import { gunzip } from 'zlib';
import { promisify } from 'util';

dotenv.config();

if (!process.env.DATABASE_URL || !process.env.CLIENT_ID || !process.env.CLIENT_SECRET) {
  throw new Error("Required environment variables (DATABASE_URL, CLIENT_ID, CLIENT_SECRET) are not set.");
}

const sql = postgres(process.env.DATABASE_URL, { ssl: false });

// Define the expected structure of each item from the API
interface Item {
  market_hash_name: string;
  min_price: number | null;
}

// Generate the Basic Authentication header
const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const encodedData = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
const authorizationHeaderString = `Basic ${encodedData}`;

// Promisified gunzip function for decompression
const gunzipAsync = promisify(gunzip);

async function populateItems() {
  try {
    const apiUrl = 'https://api.skinport.com/v1/items?app_id=730&currency=EUR&tradable=0';
    const response = await request(apiUrl, {
      method: 'GET',
      headers: {
        'Accept-Encoding': 'gzip',
        'Authorization': authorizationHeaderString, // Add the Authorization header
      },
    });

    if (response.statusCode !== 200) {
      console.error(`Failed to fetch items from Skinport API. Status code: ${response.statusCode}`);
      return;
    }

    // Get the response body as a Buffer and decompress if gzipped
    const compressedBody = await response.body.arrayBuffer();
    const decompressedBody = await gunzipAsync(Buffer.from(compressedBody));

    // Parse and cast the decompressed response to `Item[]`
    const items = JSON.parse(decompressedBody.toString()) as Item[];

    for (const item of items) {
      await sql`
        INSERT INTO items (name, tradable_price, non_tradable_price)
        VALUES (${item.market_hash_name}, ${item.min_price}, ${item.min_price})
        ON CONFLICT (name) DO NOTHING
      `;
    }

    console.log('Items populated successfully');
  } catch (error) {
    console.error('Error populating items:', error);
  } finally {
    await sql.end();
  }
}

populateItems();
