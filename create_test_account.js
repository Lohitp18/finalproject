import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'
import User from './server/models/User.js'
import dotenv from 'dotenv'

dotenv.config()

const MONGO_URL = process.env.MONGO_URL || process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-transfer'

// Test account credentials
const TEST_ACCOUNT = {
  name: 'Test User',
  email: 'test@example.com',
  password: 'Test123!@#'
}

async function createTestAccount() {
  try {
    console.log('Connecting to MongoDB...')
    await mongoose.connect(MONGO_URL)
    console.log('Connected to MongoDB')

    // Check if user already exists
    const existing = await User.findOne({ email: TEST_ACCOUNT.email })
    if (existing) {
      console.log('\n⚠️  Account already exists!')
      console.log('\n📧 Credentials:')
      console.log('   Email:', TEST_ACCOUNT.email)
      console.log('   Password:', TEST_ACCOUNT.password)
      console.log('\nYou can use these credentials to login.')
      await mongoose.disconnect()
      return
    }

    // Create new user
    console.log('Creating test account...')
    const passwordHash = await bcrypt.hash(TEST_ACCOUNT.password, 10)
    const user = await User.create({
      name: TEST_ACCOUNT.name,
      email: TEST_ACCOUNT.email,
      passwordHash: passwordHash
    })

    console.log('\n✅ Account created successfully!')
    console.log('\n📧 Login Credentials:')
    console.log('   Email:', TEST_ACCOUNT.email)
    console.log('   Password:', TEST_ACCOUNT.password)
    console.log('\n📋 Account Details:')
    console.log('   Name:', user.name)
    console.log('   User ID:', user._id.toString())
    console.log('   Created:', user.createdAt)
    console.log('\n💡 You can now use these credentials to login to the application.')

    await mongoose.disconnect()
    console.log('\nDisconnected from MongoDB')
  } catch (error) {
    console.error('Error creating account:', error)
    if (error.code === 11000) {
      console.log('\n⚠️  Account with this email already exists!')
      console.log('\n📧 Credentials:')
      console.log('   Email:', TEST_ACCOUNT.email)
      console.log('   Password:', TEST_ACCOUNT.password)
    }
    process.exit(1)
  }
}

createTestAccount()

