import { validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

export function validateRequest(req: Request, res: Response, next: NextFunction) {
    const result = validationResult(req);


    if (!result.isEmpty()) {
        const errors = result.array();


        return res.status(400).json({
            error: 'Invalid data',
            details: errors.map(e => ({
                field: (e as any).path ?? '_error',
                msg: e.msg
            }))
        });
    }


    next();
}