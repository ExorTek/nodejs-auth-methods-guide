import 'dotenv/config';
import { createExpressApp, connectMongoDB } from '@auth-guide/shared';

const PORT = process.env.PORT || 3000;

const app = createExpressApp();

await connectMongoDB(process.env.MONGODB_URI);

app.listen(PORT, () => {
  console.log(`\n🚀 Server running: http://localhost:${PORT}`);
});
