import { Router } from 'express';

const SignInRouter = Router();

SignInRouter.get('/sign-in/:email', (req, res) => {
    res.send( {title : 'GET user details'} )
})

export default SignInRouter;