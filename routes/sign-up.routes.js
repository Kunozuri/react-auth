import { Router } from 'express';

const SignUpRouter = Router();

SignUpRouter.post('/sign-up', (req, res) => {
    res.send( {title : 'POST user details'} )
})

export default SignUpRouter;