
BASICS: 

jwt.sign(payload, secret, options(expires))  --> return jwt.sign({userId: this._id}, 'jwtSecret', {expiresIn: '1d'}) 


CREATION (Mongo): 

UserSchema.methods.createJWT = function(){
  return jwt.sign({ userId: this._id}, process.env.JWT_SECRET, {expiresIn: process.env.JWT_LIFETIME }) 
} 







AUTH.js 

const token = authHeader.split(' ')[1] 

try{ 
  const payload = jwt.verify(token, process.env.JWT_SECRET) 
  console.log(payload) // ==> {userId: 'frgerf342r2f', iat:31434, exp:42123523} 
  
  req.user = payload //  ===> {userId: 'frgerf342r2f'} 
  
} 


  
CReate token every time you register, login, update 
  and then attack the cookie to the browser 
  
  
  
REGISTER 
  
  const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    throw new BadRequestError('please provide all values');
  }
  const userAlreadyExists = await User.findOne({ email });
    
  if (userAlreadyExists) {
    throw new BadRequestError('Email already in use');
  }
  const user = await User.create({ name, email, password });

  const token = user.createJWT();
  
  // attach cookie to the browser  
  attachCookie({ res, token });
  res.status(StatusCodes.CREATED).json({
    user: {
      email: user.email,
      lastName: user.lastName,
      location: user.location,
      name: user.name,
    },

    location: user.location,
  });
};
  
LOGIN: 

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new BadRequestError('Please provide all values');
  }
  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    throw new UnAuthenticatedError('Invalid Credentials');
  }

  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new UnAuthenticatedError('Invalid Credentials');
  }
  const token = user.createJWT();
  attachCookie({ res, token });
  user.password = undefined;

  res.status(StatusCodes.OK).json({ user, location: user.location });
};
  
  
UPDATE  
  - 
  
  const updateUser = async (req, res) => {
  const { email, name, lastName, location } = req.body;
  if (!email || !name || !lastName || !location) {
    throw new BadRequestError('Please provide all values');
  }
  const user = await User.findOne({ _id: req.user.userId });

  user.email = email;
  user.name = name;
  user.lastName = lastName;
  user.location = location;

  await user.save();

  const token = user.createJWT();
  attachCookie({ res, token });

  res.status(StatusCodes.OK).json({ user, location: user.location });
};
  
  
LOGOUT - 
  
remove cookie   
  
  const logout = async (req, res) => {
  res.cookie('token', 'logout' (<--this can be any name) , {
    httpOnly: true,    (<-- can be performed only through http reqs) 
    expires: new Date(Date.now() + 1000),
  });
  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};
  

  
  
  
  


POSTMAN SETTING - 
  
const jsonData = pm.response.json() 
  pm.global.set({varKey},{varValue}) 

pm.global.set("token",jsonData.token) 
  
  {{token}} variable will be created globally 





