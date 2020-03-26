const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10; //10자리
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name:{
        type: String,
        maxlength: 50
    },
    email:{
        type:String,
        trim:true
    },
    password:{
        type:String,
        minlength:5
    },
    lastname:{
        type:String,
        maxlength:50
    },
    role:{
        type:Number,
        default: 0
    },
    image:String,
    token:{
        type:String
    },
    tokenExp:{
        type:Number
    }
});

userSchema.pre('save', function(next){//save 함수가 실행되기 전에
    var user = this;

    if(user.isModified('password'))//password가 변환될때만
    {//이 조건문이 없으면 다른 요소가 변경됬을때도 save를
        //사용하므로 비밀번호가 다시 변경되는 경우 발생

        //비밀번호 암호화
        bcrypt.genSalt(saltRounds, function(err, salt){
            if(err) return next(err);
            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(err);
                user.password = hash;//hash = 새 비밀번호
                next()
            })
        });
    }else{
        next()
    }
})
//메소드 만들기
userSchema.methods.comparePassword = function(plainPassword, cb){
    //plainPassword 1234567 암호화된pw = ...~~
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if(err) return cb(err)
        cb(null, isMatch)
    })
}

userSchema.methods.generateToken = function(cb){
    var user = this;
    
    //jsonwebtoken을 이용해 token 생성
    var token = jwt.sign(user._id.toHexString(), 'secretToken')
    /*user._id + 'secretToken'= token
    ->
    'secretToken'-> user._id*/


    user.token = token
    user.save(function(err, user){
        if(err) return cb(err)
        cb(null, user)
    })
}

userSchema.statics.findByToken = function(token, cb){
    var user = this;

    //토큰을 decode 한다.
    jwt.verify(token,'secretToken' , function(err, decoded){
        //유저 아이디를 이용해서 유저를 찾은 뒤
        //클라이언트에서 가져온 토큰과 db에 보관된 토큰이
        //일치하는지 확인

        user.findOne({"_id":decoded, "token":token}, function(err, user){

            if(err) return cb(err);
            cb(null, user);            
        })
    })
}

const User = mongoose.model('User', userSchema);

module.exports = {User};