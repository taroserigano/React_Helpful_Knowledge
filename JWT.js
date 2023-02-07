
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



POSTMAN - 
  
const jsonData = pm.response.json() 
  pm.global.set({varKey},{varValue}) 

pm.global.set("token",jsonData.token) 
  
  {{token}} variable will be created globally 





