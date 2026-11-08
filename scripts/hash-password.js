const bcrypt = require('bcryptjs');
const password = process.argv[2];
if (!password || password.length < 12) {
  console.error('Usage: npm run hash-password -- "a-long-password-at-least-12-characters"');
  process.exit(1);
}
bcrypt.hash(password, 12).then((hash) => console.log(hash)).catch((error) => {
  console.error(error);
  process.exit(1);
});
