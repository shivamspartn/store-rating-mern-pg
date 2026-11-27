import { z } from "zod";

export const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(16, "Password must be at most 16 characters")
  .regex(/[A-Z]/, "Password must include at least one uppercase letter")
  .regex(/[^A-Za-z0-9]/, "Password must include at least one special character");

export const registerSchema = z.object({
  name: z.string().trim().min(20, "Name must be at least 20 characters").max(60, "Name cannot exceed 60 characters"),
  email: z.string().trim().email("Invalid email address"),
  address: z.string().trim().min(1, "Address is required").max(400, "Address cannot exceed 400 characters"),
  password: passwordSchema,
});

export const adminCreateUserSchema = registerSchema.extend({
  role: z.enum(["ADMIN", "USER", "STORE_OWNER"]),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: passwordSchema,
});