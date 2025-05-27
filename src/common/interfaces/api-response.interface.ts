export interface ApiResponse<T = any> {
  status: 0 | 1;
  message: string;
  data: T | null;
}
